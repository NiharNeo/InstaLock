"""Live HTTP misuse/valid/concurrency/bypass runner with persisted honest evidence."""
from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any
from uuid import uuid4
from urllib.parse import urlsplit
import httpx
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from app.auth.service import secret_hash
from app.core.canonical import digest, ProposedAction
from app.core.policy import PolicyEngine
from intentlock.db import AgentServiceKey, EvalRun, KeyRegistry, Operation, Order, Payment, Proposal, Receipt, UsedGrant
from tools.eval.captures import claims, validate_capture
from tools.eval.cases import suite, wire
from tools.eval.contracts import Capture, Plan
from tools.eval.observer import Observer, delta


class EvaluationStopped(RuntimeError):
    """A failed/incomplete prerequisite must not turn into a fabricated pass."""


def git_sha(root: Path) -> str | None:
    """Resolve actual checkout HEAD or explicit build provenance, never invent an SHA."""
    configured=os.environ.get('EVAL_GIT_SHA')
    if configured:
        return configured if re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',configured) else None
    try:
        result=subprocess.run(['git','rev-parse','HEAD'],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=False)
    except OSError:
        return None
    value=result.stdout.decode().strip()
    return value if result.returncode==0 and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',value) else None


def percentiles(samples: list[int]) -> dict[str,Any]:
    """Nearest-rank percentiles from actual nanosecond measurements only."""
    ordered=sorted(samples)
    return {'samples':len(ordered),**{name:(ordered[max(0,math.ceil(p*len(ordered))-1)]/1000000 if ordered else None) for name,p in [('p50_ms',0.50),('p95_ms',0.95),('p99_ms',0.99)]}}


class Runner:
    """Trusted evaluation process. HTTP never fakes provider responses or grant state."""
    def __init__(self,engine: Engine,tenant: str,url: str,agent_key: str,operator_session: str,csrf: str,origin: str,observer: Observer,*,timeout: int = 180,observe_seconds: int = 5):
        """Bind separate operator/service clients and independent actual-provider probes."""
        parsed=urlsplit(url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('','/') or not parsed.hostname or (parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1','::1','gateway'})):
            raise ValueError('PROTECTED_GATEWAY_ORIGIN_REQUIRED')
        if not 1<=timeout<=3600 or not 1<=observe_seconds<=60:
            raise ValueError('INVALID_EVAL_TIME_LIMIT')
        self.engine,self.tenant,self.observer=engine,tenant,observer
        self.agent_key=agent_key
        self.agent=httpx.Client(base_url=url.rstrip('/')+'/',headers={'Authorization':'Bearer '+agent_key},timeout=45,follow_redirects=False)
        self.operator=httpx.Client(base_url=url.rstrip('/')+'/',headers={'Cookie':'intentlock_session='+operator_session,'Origin':origin,'X-CSRF-Token':csrf},timeout=45,follow_redirects=False)
        self.timeout,self.observe_seconds=timeout,observe_seconds
        self.run_id=str(uuid4())
        self.results: list[dict[str,Any]]=[]
        self.latencies: list[int]=[]
        self.summary: dict[str,Any]={'misuse_expected':60,'valid_expected':40,'concurrent_requests_expected':50,'baseline':'NOT_RUN'}
        self.started=False

    def close(self) -> None:
        """Close secret-bearing clients without printing any configuration."""
        self.agent.close()
        self.operator.close()

    def start(self) -> None:
        """Persist RUNNING before opening captures or contacting the stack."""
        sha=git_sha(Path.cwd())
        with Session(self.engine) as session,session.begin():
            session.add(EvalRun(id=self.run_id,tenant_id=self.tenant,git_sha=sha,started_at=int(time.time()),finished_at=None,status='RUNNING',summary=self.summary,cases=[]))
        self.started=True
        if sha is None:
            raise EvaluationStopped('GIT_SHA_UNAVAILABLE')

    def save(self,status: str = 'RUNNING') -> None:
        """Checkpoint sanitized case evidence after each observation."""
        with Session(self.engine) as session,session.begin():
            row=session.get(EvalRun,self.run_id)
            if row is None:
                raise EvaluationStopped('EVAL_HISTORY_UNAVAILABLE')
            row.status=status
            row.finished_at=None if status=='RUNNING' else int(time.time())
            row.summary={**self.summary,'gateway_path_overhead_valid':percentiles(self.latencies),'timing_method':'gateway monotonic duration minus union of actual executor provider I/O spans; no response stubs'}
            def sanitized(value):
                if isinstance(value,dict):
                    return {('receipt_ref_hash' if key=='receipt' else key):(hashlib.sha256(str(item).encode()).hexdigest() if key=='receipt' else sanitized(item)) for key,item in value.items()}
                if isinstance(value,list):
                    return [sanitized(item) for item in value]
                return value
            row.cases=sanitized(self.results)

    def preflight(self,plan: Plan) -> None:
        """Require real captures, live scoped sessions, expired/used/webhook history."""
        response=self.operator.get('v1/eval-runs',params={'limit':'1'})
        response.raise_for_status()
        if response.json().get('tenant_id')!=self.tenant:
            raise EvaluationStopped('OPERATOR_TENANT_MISMATCH')
        if response.json().get('execution_mode')!='trusted-executor' or response.json().get('provider_timing')!='monotonic-real-provider-spans-v1':
            raise EvaluationStopped('LIVE_TRUSTED_EXECUTOR_REQUIRED')
        stale=[]
        now=int(time.time())
        by_name={c.name:c for c in plan.captures}
        with Session(self.engine) as session:
            agent=session.scalar(select(AgentServiceKey).where(AgentServiceKey.token_hash==secret_hash(self.agent_key),AgentServiceKey.active.is_(True)))
            if agent is None or agent.tenant_id!=self.tenant or agent.expires_at<=now:
                raise EvaluationStopped('ACTUAL_AGENT_KEY_REQUIRED')
            self.actor=agent.actor_id
            for capture in plan.captures:
                validate_capture(session,capture,self.tenant)
                if capture.action.actor_id!=agent.actor_id:
                    raise EvaluationStopped('CAPTURE_SERVICE_ACTOR_MISMATCH')
                grant=session.get(UsedGrant,claims(capture.grant_token)['jti'])
                assert grant is not None
                if capture.role=='expired' and (grant.expires_at is None or grant.expires_at>now):
                    raise EvaluationStopped('ACTUALLY_EXPIRED_GRANT_REQUIRED')
                if capture.role in ('fresh','stale','different_tool') and (grant.expires_at is None or grant.expires_at<=now):
                    raise EvaluationStopped('HISTORICAL_GRANT_ALREADY_EXPIRED')
                if capture.role=='stale':
                    stale.append(grant.id)
                if capture.role not in ('different_tool',) and session.get(Proposal,capture.proposal_id).service_id!=agent.id:
                    raise EvaluationStopped('CAPTURE_SERVICE_KEY_MISMATCH')
            if len(set(stale))<4:
                raise EvaluationStopped('FOUR_DISTINCT_STALE_GRANTS_REQUIRED')
            base=by_name[plan.base_id].action.args.payment_id
            alternate=by_name[plan.alternate_id].action.args.payment_id
            foreign=session.get(Payment,plan.foreign_payment_id)
            if base==alternate or foreign is None or foreign.tenant_id==self.tenant:
                raise EvaluationStopped('ACTUAL_ALTERNATE_AND_OTHER_TENANT_PAYMENT_REQUIRED')
            self.foreign_tenant=foreign.tenant_id
            for name in [*plan.valid_ids,plan.concurrency_id]:
                if by_name[name].role!='fresh':
                    raise EvaluationStopped('VALID_WORKLOAD_MUST_USE_FRESH_CAPTURES')
        evidence=self.observer.snapshot([*{c.action.args.payment_id for c in plan.captures},plan.foreign_payment_id])
        policy=PolicyEngine.load(Path(os.environ['EVAL_POLICY_FILE']))
        with Session(self.engine) as session:
            audit=session.get(Receipt,response.json()['receipt_id'])
            if audit is None or audit.policy_version!=policy.policy_version:
                raise EvaluationStopped('DEPLOYED_POLICY_FILE_MISMATCH')
            if session.scalar(select(Operation.id).where(Operation.tenant_id==self.tenant,Operation.status=='PENDING')) is not None:
                raise EvaluationStopped('QUIESCENT_TEST_TENANT_REQUIRED')
        config=policy.tenants.get(self.tenant)
        if config is None or 'refund.create' not in config.tools:
            raise EvaluationStopped('EXPLICIT_REFUND_POLICY_REQUIRED')
        required: dict[str,int]={}
        for name in [*plan.valid_ids,plan.concurrency_id]:
            action=by_name[name].action
            required[action.args.payment_id]=required.get(action.args.payment_id,0)+action.args.amount_paise
        for payment_id,amount in required.items():
            live=evidence['payments'][payment_id]['payment']
            if live['amount_refunded_paise']+amount>min(live['amount_paise'],config.max_refund_paise):
                raise EvaluationStopped('INSUFFICIENT_REAL_REFUND_CAPACITY_FOR_41_ALLOWS')
        self.summary['preflight']='LIVE_STACK_AND_CAPTURE_PROVENANCE_VERIFIED'
        self.save()

    def approve(self,capture: Capture) -> tuple[dict[str,Any],str]:
        """Obtain a new real human-session approval, preserving captured financial values."""
        action=capture.action.model_dump(mode='json')
        with Session(self.engine) as session:
            order=session.get(Order,action['resource_ref'])
            if order is None or order.tenant_id!=self.tenant:
                raise EvaluationStopped('CAPTURE_RESOURCE_MISSING')
            action['resource_version']=order.version
        proposed=self.agent.post('v1/proposals',json=action)
        if proposed.status_code!=201:
            raise EvaluationStopped('FRESH_PROPOSAL_NOT_ADMISSIBLE')
        identifier=proposed.json()['proposal_id']
        preview=self.operator.get('v1/proposals/'+identifier+'/preview')
        if preview.status_code!=200 or preview.json().get('action')!=action:
            raise EvaluationStopped('LIVE_PREVIEW_FAILED')
        response=self.operator.post('v1/proposals/'+identifier+'/approve',json={})
        if response.status_code!=200:
            raise EvaluationStopped('OPERATOR_APPROVAL_FAILED')
        token=response.json()['grant_token']
        with Session(self.engine) as session:
            row=session.get(UsedGrant,claims(token)['jti'])
            if row is None or row.status!='ACTIVE' or row.token_hash!=hashlib.sha256(token.encode()).hexdigest():
                raise EvaluationStopped('APPROVAL_NOT_IN_DATABASE')
        return action,token

    def send(self,raw: bytes,key: str) -> dict[str,Any]:
        """Send original wire bytes to the live gateway, measuring actual round-trip time."""
        started=time.perf_counter_ns()
        response=self.agent.post('v1/execute',content=raw,headers={'Content-Type':'application/json','Idempotency-Key':key})
        elapsed=time.perf_counter_ns()-started
        try:
            body=response.json()
        except Exception:
            raise EvaluationStopped('GATEWAY_NON_JSON_RESPONSE') from None
        timing=None
        if response.headers.get('X-IntentLock-Timing-Valid')=='1':
            total=int(response.headers['X-IntentLock-Gateway-Ns'])
            provider=int(response.headers['X-IntentLock-Provider-Ns'])
            if 0<=provider<=total:
                timing={'gateway_ns':total,'provider_io_ns':provider,'overhead_ns':total-provider,'client_roundtrip_ns':elapsed}
        return {'http_status':response.status_code,'reason':body.get('reason'),'allowed':body.get('allowed'),'operation_id':body.get('operation_id'),'timing':timing}

    def wait_operation(self,jti: str) -> Operation:
        """Wait for the actual stack/reconciler to settle; never update grant/provider state."""
        deadline=time.monotonic()+self.timeout
        while time.monotonic()<deadline:
            with Session(self.engine) as session:
                row=session.scalar(select(Operation).where(Operation.grant_jti==jti,Operation.tenant_id==self.tenant))
                if row is not None and row.status!='PENDING':
                    session.expunge(row)
                    return row
            time.sleep(1)
        raise EvaluationStopped('REAL_OPERATION_DID_NOT_SETTLE')

    def misuse(self,plan: Plan) -> None:
        """Execute exactly sixty wire attacks; require exact codes and zero new refunds."""
        by_name={c.name:c for c in plan.captures}
        for case in suite(plan):
            historical=case.kind in {'expired_grant','replayed_new_key','stale_after_webhook','different_tool_grant'}
            action,token=(case.capture.action.model_dump(mode='json'),case.capture.grant_token) if historical else self.approve(case.capture)
            if case.kind not in ('expired_grant','replayed_new_key') and claims(token)['exp']<=int(time.time()):
                raise EvaluationStopped('CAPTURE_EXPIRED_BEFORE_CASE')
            with Session(self.engine) as session:
                registry=session.get(KeyRegistry,session.get(UsedGrant,claims(token)['jti']).kid)
                public=base64.b64decode(registry.public_key,validate=True)
            raw=wire(case,action,token,alternate_payment=by_name[plan.alternate_id].action.args.payment_id,foreign_payment=plan.foreign_payment_id,foreign_tenant=self.foreign_tenant,public_key=public)
            watch=[action['args']['payment_id']]
            if case.kind=='changed_payment_id':
                watch.append(by_name[plan.alternate_id].action.args.payment_id)
            if case.kind=='other_tenant_payment':
                watch.append(plan.foreign_payment_id)
            before=self.observer.snapshot(watch)
            key=self.run_id+'-misuse-'+str(case.index)
            response=self.send(raw,key)
            time.sleep(self.observe_seconds)
            after=self.observer.snapshot(watch)
            evidence=delta(before,after)
            with Session(self.engine) as session:
                op=session.scalar(select(Operation).where(Operation.tenant_id==self.tenant,Operation.idempotency_key==key))
                pending=op is not None and op.status=='PENDING'
            passed=response['reason']==case.expected and response['allowed'] is False and not evidence['db_refund_ids'] and not evidence['provider_refunds'] and all(n==0 for n in evidence['balance_delta_paise'].values()) and not pending
            self.results.append({'phase':'misuse','case':case.index,'kind':case.kind,'capture_id':case.capture.name,'ticket_id':case.capture.ticket_id,'grant_jti':claims(token)['jti'],'expected':case.expected,'request_hash':hashlib.sha256(raw).hexdigest(),'source_action_digest':digest(ProposedAction.model_validate(action)),'observed_reason':response['reason'],'passed':passed,'observation_seconds':self.observe_seconds,**evidence})
            self.summary['misuse_attempted']=sum(r['phase']=='misuse' for r in self.results)
            self.summary['misuse_passed']=sum(r['phase']=='misuse' and r['passed'] for r in self.results)
            self.save()
            if not passed:
                raise EvaluationStopped('MISUSE_EXACT_REASON_OR_ZERO_REFUND_FAILED')

    def valid(self,plan: Plan) -> None:
        """Complete forty real operator-approved refunds, checking SQL and provider IDs."""
        by_name={c.name:c for c in plan.captures}
        for index,name in enumerate(plan.valid_ids,1):
            capture=by_name[name]
            action,token=self.approve(capture)
            payment=action['args']['payment_id']
            before=self.observer.snapshot([payment])
            response=self.send(json.dumps({'action':action,'grant_token':token}).encode(),self.run_id+'-valid-'+str(index))
            operation=self.wait_operation(claims(token)['jti'])
            after=self.observer.snapshot([payment])
            evidence=delta(before,after)
            provider=[row for row in evidence['provider_refunds'] if row['provider_id']==operation.provider_refund_id and row['status']=='processed' and row['amount_paise']==action['args']['amount_paise'] and row['receipt']==operation.id]
            passed=operation.status=='DONE' and len(evidence['db_refund_ids'])==len(evidence['provider_refunds'])==len(provider)==1 and evidence['db_refund_ids'][0]==operation.provider_refund_id and evidence['balance_delta_paise'][payment]==action['args']['amount_paise'] and response['timing'] is not None
            if response['timing']:
                self.latencies.append(response['timing']['overhead_ns'])
            self.results.append({'phase':'valid','case':index,'capture_id':name,'ticket_id':capture.ticket_id,'operation_id':operation.id,'grant_jti':operation.grant_jti,'action_digest':claims(token)['act_digest'],'passed':passed,'observed_reason':operation.reason,'timing':response['timing'],**evidence})
            self.summary['valid_attempted']=index
            self.summary['valid_completed']=sum(r['phase']=='valid' and r['passed'] for r in self.results)
            self.save()
            if not passed:
                raise EvaluationStopped('VALID_REFUND_OR_REAL_TIMING_FAILED')

    def concurrency(self,plan: Plan) -> None:
        """Send fifty distinct idempotency keys with one real grant, assert one refund."""
        capture=next(c for c in plan.captures if c.name==plan.concurrency_id)
        action,token=self.approve(capture)
        payment=action['args']['payment_id']
        before=self.observer.snapshot([payment])
        raw=json.dumps({'action':action,'grant_token':token}).encode()
        with ThreadPoolExecutor(max_workers=50) as pool:
            responses=list(pool.map(lambda n:self.send(raw,self.run_id+'-race-'+str(n)),range(50)))
        operation=self.wait_operation(claims(token)['jti'])
        after=self.observer.snapshot([payment])
        evidence=delta(before,after)
        passed=operation.status=='DONE' and len(evidence['db_refund_ids'])==len(evidence['provider_refunds'])==1 and evidence['db_refund_ids'][0]==operation.provider_refund_id==evidence['provider_refunds'][0]['provider_id'] and evidence['provider_refunds'][0]['status']=='processed' and evidence['balance_delta_paise'][payment]==action['args']['amount_paise'] and sum(r['reason']=='GRANT_USED' for r in responses)==49
        self.results.append({'phase':'concurrency','requests':50,'passed':passed,'operation_id':operation.id,'grant_jti':operation.grant_jti,'action_digest':claims(token)['act_digest'],'reason_counts':{str(reason):sum(r['reason']==reason for r in responses) for reason in {r['reason'] for r in responses}},**evidence})
        self.summary['concurrency_passed']=passed
        self.save()
        if not passed:
            raise EvaluationStopped('CONCURRENCY_EXACTLY_ONE_REFUND_FAILED')

    def baseline(self,plan: Plan,budget: int) -> None:
        """Make real direct-provider attempts AFTER defended suites; never simulate impact."""
        if type(budget) is not int or budget<=0:
            raise EvaluationStopped('EXPLICIT_BASELINE_PAISE_BUDGET_REQUIRED')
        by_name={c.name:c for c in plan.captures}
        reserved=0
        self.summary['baseline']='RUNNING_REAL_PROVIDER_BYPASS'
        for case in suite(plan):
            capture=case.capture
            action=capture.action.model_dump(mode='json')
            # Mutated amount differs by at most one paise; reserve a conservative
            # bound before any unsafe POST, including rejected/unknown attempts.
            charge=action['args']['amount_paise']+1
            if reserved+charge>budget:
                raise EvaluationStopped('BASELINE_BUDGET_EXHAUSTED')
            reserved+=charge
            with Session(self.engine) as session:
                grant=session.get(UsedGrant,claims(capture.grant_token)['jti'])
                public=base64.b64decode(session.get(KeyRegistry,grant.kid).public_key)
            raw=wire(case,action,capture.grant_token,alternate_payment=by_name[plan.alternate_id].action.args.payment_id,foreign_payment=plan.foreign_payment_id,foreign_tenant=self.foreign_tenant,public_key=public)
            watch=[action['args']['payment_id'],by_name[plan.alternate_id].action.args.payment_id,plan.foreign_payment_id]
            before=self.observer.snapshot(watch)
            result=self.observer.call(self.tenant,{'op':'baseline','wire':raw.decode(),'reference':str(uuid4())},bypass=True)
            time.sleep(self.observe_seconds)
            after=self.observer.snapshot(watch)
            evidence=delta(before,after)
            self.results.append({'phase':'baseline','case':case.index,'kind':case.kind,'outcome':result['outcome'],'provider_post_attempted':result['outcome']!='NOT_REPRESENTABLE','reserved_budget_paise':charge,**evidence})
            self.summary['baseline_attempted']=sum(r['phase']=='baseline' for r in self.results)
            self.summary['baseline_provider_posts']=sum(r.get('provider_post_attempted',False) for r in self.results if r['phase']=='baseline')
            self.summary['baseline_not_representable']=sum(r['outcome']=='NOT_REPRESENTABLE' for r in self.results if r['phase']=='baseline')
            self.summary['baseline_actual_provider_refunds']=sum(len(r['provider_refunds']) for r in self.results if r['phase']=='baseline')
            self.summary['baseline_budget_reserved_paise']=reserved
            self.save()
            if result['outcome']=='PROVIDER_UNCERTAIN':
                raise EvaluationStopped('BASELINE_PROVIDER_OUTCOME_UNKNOWN')
        self.summary['baseline']='COMPLETED_REAL_BYPASS_PROJECTION'

    def run(self,plan: Plan,*,baseline_budget: int | None = None) -> str:
        """Run all required phases and checkpoint failures without persisting secrets."""
        self.preflight(plan)
        self.misuse(plan)
        self.valid(plan)
        self.concurrency(plan)
        if baseline_budget is None:
            self.summary['stop_reason']='BASELINE_NOT_REQUESTED'
            self.save('INCOMPLETE')
            return 'INCOMPLETE'
        self.baseline(plan,baseline_budget)
        self.save('PASS')
        return 'PASS'
