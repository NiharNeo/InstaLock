"""Tenant-scoped v1 gateway workflows with server-built consent previews."""
from __future__ import annotations

import hashlib
import hmac
import re
import time
from typing import Any
from uuid import uuid4

import rfc8785
from pydantic import Field
from sqlalchemy import select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.adapters.payments import ResourceAdapter
from app.auth.service import authenticate_agent, authenticate_operator, operator_session, check_csrf
from app.config import GatewaySettings
from app.core.canonical import ProposedAction, _Contract, digest, parse_action
from app.core.errors import GatewayDenied, enforce
from app.core.grants import GrantIssueError, GrantService, GrantSettings
from app.core.orchestrator import RefundOrchestrator
from app.core.keys import load_private_key_for_kid
from app.core.policy import PaymentSnapshot, PolicyEngine
from app.core.receipts import append_receipt
from intentlock.db import ApprovalDispatch, Execution, OperatorSession, Proposal, ProposalPreview, Receipt, UsedGrant


class ExecuteRequest(_Contract):
    """Only an exact typed action and human-issued bearer grant may be submitted."""
    action: ProposedAction
    grant_token: str = Field(strict=True,min_length=1,max_length=16384)


class SessionRequest(_Contract):
    """Existing human session credentials; no session is created by this request."""
    session_token: str = Field(strict=True,pattern=r'^[A-Za-z0-9_-]{40,128}$')
    csrf_token: str = Field(strict=True,pattern=r'^[A-Za-z0-9_-]{40,128}$')


class ApproveRequest(_Contract):
    """An empty approval body; client digests and changed arguments are forbidden."""


def fingerprint(value: dict[str,Any]) -> str:
    """Hash structured metadata without lossy or order-dependent concatenation."""
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


class Gateway:
    """Transaction boundary for authenticated proposals, previews, consent and effects."""
    def __init__(self, engine: Engine, settings: GatewaySettings, policy: PolicyEngine, adapter: ResourceAdapter, orchestrator: RefundOrchestrator):
        """Bind live components and the immutable startup policy snapshot."""
        self.engine,self.settings,self.policy,self.adapter,self.orchestrator = engine,settings,policy,adapter,orchestrator
        self.executor = None

    def audit(self, session: Session, raw: bytes, reason: str, rule_id: str, allowed: bool, *, action: ProposedAction | None = None, request_id: str | None = None, refund_id: str | None = None) -> str:
        """Write minimal decision evidence in the same transaction as any allow."""
        receipt_id = str(uuid4())
        proposal=session.get(Proposal,request_id) if request_id and action is not None else None
        append_receipt(session,tenant_id=session.info.get('receipt_tenant') or (action.tenant_id if action else None),actor_id=session.info.get('receipt_actor') or (action.actor_id if action else None),grant_jti=proposal.grant_id if proposal else None,id=receipt_id,timestamp=int(time.time()),allowed=allowed,reason=reason,rule_id=rule_id,policy_version=self.policy.policy_version,input_hash=hashlib.sha256(raw).hexdigest(),action_digest=digest(action).removeprefix('sha256:') if action else None,request_id=request_id,refund_id=refund_id)
        session.flush()
        return receipt_id

    def deny(self, raw: bytes, failure: GatewayDenied, tenant_id: str | None = None, actor_id: str | None = None) -> tuple[dict[str,Any],int]:
        """Persist a denial after rollback; a failed audit can never return allow."""
        try:
            with Session(self.engine) as session, session.begin():
                session.info.update(receipt_tenant=tenant_id,receipt_actor=actor_id)
                receipt_id = self.audit(session,raw,failure.reason,failure.rule_id,False)
            return {'allowed':False,'reason':failure.reason,'rule_id':failure.rule_id,'policy_version':self.policy.policy_version,'receipt_id':receipt_id},failure.status
        except Exception:
            return {'allowed':False,'reason':'AUDIT_UNAVAILABLE','rule_id':'audit.required','policy_version':self.policy.policy_version},503

    def login(self, request: Request, raw: bytes, data: Any) -> dict[str,Any]:
        """Exchange an already provisioned human session for a protected cookie."""
        with Session(self.engine) as session, session.begin():
            if request.headers.get('authorization'):
                raise GatewayDenied('UNAUTHENTICATED','auth.operator_session',401)
            body = SessionRequest.model_validate(data)
            identity,row = operator_session(session,body.session_token)
            request.state.receipt_tenant=identity.tenant_id
            request.state.receipt_actor=identity.operator_id
            check_csrf(request,body.csrf_token,row,self.settings.origin)
            receipt_id = self.audit(session,raw,'SESSION_AUTHENTICATED','auth.operator_session',True)
            result = {'allowed':True,'reason':'SESSION_AUTHENTICATED','rule_id':'auth.operator_session','policy_version':self.policy.policy_version,'operator_id':identity.operator_id,'tenant_id':identity.tenant_id,'receipt_id':receipt_id,'_cookie_token':body.session_token,'_cookie_max_age':row.expires_at-int(time.time())}
        return result

    def logout(self, request: Request, raw: bytes) -> dict[str,Any]:
        """Revoke this human session with CSRF protection before clearing its cookie."""
        with Session(self.engine) as session, session.begin():
            human = authenticate_operator(session,request,csrf=True,origin=self.settings.origin)
            session.execute(update(OperatorSession).where(OperatorSession.id == human.session_id).values(active=False))
            receipt_id = self.audit(session,raw,'SESSION_REVOKED','auth.operator_session',True)
            result = {'allowed':True,'reason':'SESSION_REVOKED','rule_id':'auth.operator_session','policy_version':self.policy.policy_version,'receipt_id':receipt_id}
        return result

    def _proposal(self, session: Session, proposal_id: str, tenant_id: str) -> tuple[Proposal,ProposedAction]:
        row = session.scalar(select(Proposal).where(Proposal.id == proposal_id,Proposal.tenant_id == tenant_id))
        if row is None:
            raise GatewayDenied('PROPOSAL_NOT_FOUND','proposal.tenant_lookup',404)
        action = parse_action(row.action)
        if action.tenant_id != tenant_id or not hmac.compare_digest(digest(action),row.action_digest):
            raise GatewayDenied('ACTION_MISMATCH','proposal.integrity')
        if row.policy_version != self.policy.policy_version:
            raise GatewayDenied('POLICY_CHANGED','proposal.policy_version')
        return row,action

    def _resource(self, session: Session, action: ProposedAction, tenant_id: str, *, for_update: bool = False) -> PaymentSnapshot:
        return self.adapter.fetch(session,action.args.payment_id,tenant_id,for_update=for_update)

    def submit(self, request: Request, raw: bytes, data: Any) -> dict[str,Any]:
        """Strictly validate an agent proposal and store only a policy-approved preview request."""
        with Session(self.engine) as session, session.begin():
            agent = authenticate_agent(session,request)
            action = parse_action(data)
            if action.tenant_id != agent.tenant_id:
                raise GatewayDenied('WRONG_TENANT','auth.agent_tenant')
            if action.actor_id != agent.actor_id:
                raise GatewayDenied('ACTOR_MISMATCH','auth.agent_actor')
            resource = self._resource(session,action,agent.tenant_id)
            decision = self.policy.evaluate(action,resource,agent.tenant_id)
            enforce(decision)
            proposal_id = str(uuid4())
            action_hash = digest(action)
            session.add(Proposal(id=proposal_id,tenant_id=agent.tenant_id,service_id=agent.service_id,action=action.model_dump(mode='json'),action_digest=action_hash,policy_version=self.policy.policy_version,status='PENDING',grant_id=None,created_at=int(time.time())))
            receipt_id = self.audit(session,raw,'PROPOSAL_ACCEPTED',decision.rule_id,True,action=action,request_id=proposal_id)
            result = {'allowed':True,'reason':'PROPOSAL_ACCEPTED','rule_id':decision.rule_id,'policy_version':self.policy.policy_version,'proposal_id':proposal_id,'action_digest':action_hash,'receipt_id':receipt_id}
        return result

    def preview(self, request: Request, raw: bytes, proposal_id: str) -> dict[str,Any]:
        """Fetch live state and record exactly what this authenticated human reviewed."""
        with Session(self.engine) as session, session.begin():
            human = authenticate_operator(session,request,origin=self.settings.origin)
            row,action = self._proposal(session,proposal_id,human.tenant_id)
            if row.status != 'PENDING':
                raise GatewayDenied('PROPOSAL_ALREADY_APPROVED','proposal.pending')
            resource = self._resource(session,action,human.tenant_id)
            enforce(self.policy.evaluate_read(scope='payment.read',tenant_id=human.tenant_id,resource=resource))
            decision = self.policy.evaluate(action,resource,human.tenant_id)
            enforce(decision)
            values = dict(resource_fingerprint=fingerprint(resource.model_dump()),action_digest=digest(action),policy_version=self.policy.policy_version,created_at=int(time.time()))
            viewed = session.get(ProposalPreview,(proposal_id,human.session_id))
            if viewed is None:
                session.add(ProposalPreview(proposal_id=proposal_id,session_id=human.session_id,**values))
            else:
                for key,value in values.items():
                    setattr(viewed,key,value)
            receipt_id = self.audit(session,raw,'PREVIEW_READY',decision.rule_id,True,action=action,request_id=proposal_id)
            result = {'allowed':True,'reason':'PREVIEW_READY','rule_id':decision.rule_id,'policy_version':self.policy.policy_version,'proposal_id':proposal_id,'action':action.model_dump(mode='json'),'action_digest':digest(action),'preview':{'payment_id':resource.payment_id,'order_id':resource.order_id,'amount_paise':action.args.amount_paise,'currency':resource.currency,'destination':'original_payment','original_payment_destination':resource.original_destination,'order_version':resource.order_version,'remaining_refundable_paise':resource.remaining_refundable_paise},'receipt_id':receipt_id}
        return result

    def approve(self, request: Request, raw: bytes, proposal_id: str, data: Any, *, deliver: bool = False) -> dict[str,Any]:
        """Re-fetch, recompute, require the viewed effect, and issue consent atomically."""
        with Session(self.engine) as session, session.begin():
            human = authenticate_operator(session,request,csrf=True,origin=self.settings.origin)
            ApproveRequest.model_validate(data)
            row,action = self._proposal(session,proposal_id,human.tenant_id)
            cipher=None
            if deliver:
                if self.executor is None:
                    raise GatewayDenied('EXECUTOR_UNAVAILABLE','dispatch.required',503)
                from app.core.dispatch import load_dispatch_cipher
                try:
                    cipher=load_dispatch_cipher()
                except Exception:
                    raise GatewayDenied('DISPATCH_UNAVAILABLE','dispatch.required',503) from None
                prior=session.get(ApprovalDispatch,proposal_id)
                if prior is not None:
                    receipt_id=self.audit(session,raw,'DISPATCH_ALREADY_QUEUED','dispatch.idempotency',True,action=action,request_id=proposal_id)
                    return {'allowed':True,'reason':'DISPATCH_ALREADY_QUEUED','proposal_id':proposal_id,'dispatch_status':prior.status,'operation_id':prior.operation_id,'receipt_id':receipt_id,'_http_status':202}
            if row.status != 'PENDING':
                raise GatewayDenied('PROPOSAL_ALREADY_APPROVED','proposal.pending')
            resource = self._resource(session,action,human.tenant_id,for_update=True)
            enforce(self.policy.evaluate_read(scope='payment.read',tenant_id=human.tenant_id,resource=resource))
            decision = self.policy.evaluate(action,resource,human.tenant_id)
            enforce(decision)
            action_hash = digest(action)
            viewed = session.get(ProposalPreview,(proposal_id,human.session_id))
            if viewed is None:
                raise GatewayDenied('PREVIEW_REQUIRED','approval.human_preview')
            if viewed.policy_version != self.policy.policy_version or not hmac.compare_digest(viewed.action_digest,action_hash) or not hmac.compare_digest(viewed.resource_fingerprint,fingerprint(resource.model_dump())):
                raise GatewayDenied('PREVIEW_STALE','approval.reviewed_effect')
            grant_service = GrantService(self.engine,GrantSettings(issuer=self.settings.issuer,policy_version=self.policy.policy_version,signing_kid=human.signing_kid),private_key_loader=lambda: load_private_key_for_kid(human.signing_kid))
            token = grant_service.issue_grant(action_hash,human.operator_id,human.tenant_id,resource.order_version,session=session)
            grant = session.scalar(select(UsedGrant).where(UsedGrant.token_hash == hashlib.sha256(token.encode()).hexdigest()))
            if grant is None:
                raise GatewayDenied('INTERNAL_ERROR','approval.issued_grant',503)
            changed = session.execute(update(Proposal).where(Proposal.id == proposal_id,Proposal.status == 'PENDING',Proposal.tenant_id == human.tenant_id).values(status='APPROVED',grant_id=grant.id,approved_resource_fingerprint=fingerprint(resource.model_dump()),approved_version_hash=resource.version_hash,approved_amount_refunded_paise=resource.refunded_paise))
            if changed.rowcount != 1:
                raise GatewayDenied('PROPOSAL_ALREADY_APPROVED','proposal.pending')
            receipt_id = self.audit(session,raw,'APPROVED','approval.human_consent',True,action=action,request_id=proposal_id)
            if deliver:
                assert cipher is not None
                now=int(time.time())
                session.add(ApprovalDispatch(proposal_id=proposal_id,tenant_id=human.tenant_id,token_ciphertext=cipher.encrypt(token.encode()).decode(),idempotency_key='approval-'+grant.id,status='QUEUED',reason='APPROVED',operation_id=None,created_at=now,next_attempt_at=now,lease_owner=None,lease_until=None))
            result = {'allowed':True,'reason':'APPROVED','rule_id':'approval.human_consent','policy_version':self.policy.policy_version,'proposal_id':proposal_id,'grant_token':token,'action_digest':action_hash,'expires_at':grant.payload['exp'],'receipt_id':receipt_id}
            if deliver:
                result.pop('grant_token')
                result.update(dispatch_status='QUEUED',_http_status=202)
        return result

    def execute(self, request: Request, raw: bytes, data: Any) -> dict[str,Any]:
        """Verify consent, evaluate live policy, and atomically orchestrate one effect."""
        if self.executor is not None:
            with Session(self.engine) as session:
                agent=authenticate_agent(session,request)
                body=ExecuteRequest.model_validate(data)
                if body.action.tenant_id!=agent.tenant_id or body.action.actor_id!=agent.actor_id:
                    raise GatewayDenied('WRONG_TENANT','auth.agent_scope')
                key=request.headers.get('idempotency-key')
                if key is None:
                    raise GatewayDenied('IDEMPOTENCY_KEY_REQUIRED','execution.idempotency',400)
                if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',key):
                    raise GatewayDenied('INVALID_IDEMPOTENCY_KEY','execution.idempotency',400)
                service_id=agent.service_id
            return self.executor.call('internal/execute',{'action':body.action.model_dump(mode='json'),'grant_token':body.grant_token,'idempotency_key':key,'service_id':service_id})
        with Session(self.engine) as session, session.begin():
            agent = authenticate_agent(session,request)
            body = ExecuteRequest.model_validate(data)
            action = body.action
            if action.tenant_id != agent.tenant_id:
                raise GatewayDenied('WRONG_TENANT','auth.agent_tenant')
            if action.actor_id != agent.actor_id:
                raise GatewayDenied('ACTOR_MISMATCH','auth.agent_actor')
            idempotency_key = request.headers.get('idempotency-key')
            if idempotency_key is None:
                raise GatewayDenied('IDEMPOTENCY_KEY_REQUIRED','execution.idempotency',400)
            if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',idempotency_key):
                raise GatewayDenied('INVALID_IDEMPOTENCY_KEY','execution.idempotency',400)
            execution_id = 'v1:' + fingerprint({'tenant':agent.tenant_id,'service':agent.service_id,'key':idempotency_key})
            request_hash = fingerprint({'action':action.model_dump(mode='json'),'grant_hash':hashlib.sha256(body.grant_token.encode()).hexdigest()})
            prior = session.get(Execution,execution_id)
            if prior is not None:
                if not hmac.compare_digest(prior.fingerprint,request_hash):
                    raise GatewayDenied('IDEMPOTENCY_CONFLICT','execution.idempotency',409)
                result = {**prior.result,'reason':'IDEMPOTENT_RETRY','rule_id':'execution.idempotent_retry','policy_version':self.policy.policy_version,'execution_policy_version':prior.result['policy_version']}
                result['receipt_id'] = self.audit(session,raw,'IDEMPOTENT_RETRY','execution.idempotent_retry',True,action=action,refund_id=result['refund_id'])
                return result
            resource = self._resource(session,action,agent.tenant_id,for_update=True)
            grant_service = GrantService(self.engine,GrantSettings(issuer=self.settings.issuer,policy_version=self.policy.policy_version))
            verified = grant_service.verify_grant(body.grant_token,digest(action),agent.tenant_id,resource.order_version,session=session)
            if not verified.allowed:
                assert verified.reason is not None
                raise GatewayDenied(verified.reason.value,'grant.'+verified.reason.value.lower(),503 if verified.reason.value in {'AUDIT_UNAVAILABLE','INTERNAL_ERROR'} else 403)
            assert verified.claims is not None
            proposal = session.scalar(select(Proposal).where(Proposal.grant_id == verified.claims.jti,Proposal.tenant_id == agent.tenant_id,Proposal.service_id == agent.service_id))
            if proposal is None or proposal.status != 'APPROVED':
                raise GatewayDenied('PROPOSAL_NOT_APPROVED','execution.approved_proposal')
            if proposal.policy_version != self.policy.policy_version:
                raise GatewayDenied('POLICY_CHANGED','execution.approved_policy')
            if not hmac.compare_digest(proposal.action_digest,digest(action)):
                raise GatewayDenied('ACTION_MISMATCH','execution.approved_action')
            decision = self.policy.evaluate(action,resource,agent.tenant_id)
            enforce(decision)
            if proposal.approved_resource_fingerprint is None or not hmac.compare_digest(proposal.approved_resource_fingerprint,fingerprint(resource.model_dump())):
                raise GatewayDenied('STALE_RESOURCE','execution.approved_resource')
            refund_id = self.orchestrator.execute(session,action,resource,verified.claims.jti,proposal.id)
            receipt_id = self.audit(session,raw,'EXECUTED',decision.rule_id,True,action=action,request_id=proposal.id,refund_id=refund_id)
            result = {'allowed':True,'reason':'EXECUTED','rule_id':decision.rule_id,'policy_version':self.policy.policy_version,'refund_id':refund_id,'action_digest':digest(action),'receipt_id':receipt_id}
            session.add(Execution(id=execution_id,fingerprint=request_hash,result=result))
        return result
