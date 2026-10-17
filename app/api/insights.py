"""Real tenant analytics and versioned human-managed refund restrictions."""
import hashlib
import time
from collections import Counter
from datetime import datetime,timedelta
from zoneinfo import ZoneInfo
from typing import Any
from uuid import uuid4
import rfc8785
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from sqlalchemy import select,func,or_
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.auth.service import authenticate_operator
from app.core.business_policy import RefundRules,effective_policy,lock_tenant_policy
from app.core.canonical import _Contract,_load_json
from app.core.errors import GatewayDenied
from app.core.receipts import reserve_audit_transaction
from intentlock.db import BusinessRefundPolicy,RefundPolicyRevision,Operation,Order,Payment,Resource,ModelCall,Receipt,Ticket

router=APIRouter()
TZ=ZoneInfo('Asia/Kolkata')
LIMIT=100000


class PolicyUpdate(_Contract):
    """Optimistic policy edit; clients cannot select a tenant or author identity."""
    expected_revision: str | None
    rules: RefundRules


def validate_headers(request: Request) -> None:
    """Reject ambiguous authentication and request headers before reading business data."""
    if any(len(request.headers.getlist(h))>1 for h in ('cookie','origin','authorization','content-type','x-csrf-token')):raise GatewayDenied('AMBIGUOUS_HEADERS','insights.headers',400)


def policy_payload(session: Session,gateway: Any,tenant: str) -> dict[str,Any]:
    """Read the actual revision and effective ceiling; never activate example defaults."""
    policy=effective_policy(session,gateway.policy,tenant)
    head=session.get(BusinessRefundPolicy,tenant)
    row=session.get(RefundPolicyRevision,head.revision_id) if head else None
    ceiling=gateway.policy.tenants.get(tenant)
    return {'revision_id':row.id if row else None,'rules':row.rules if row else None,'created_at':row.created_at if row else None,'created_by':row.created_by if row else None,'policy_version':policy.policy_version,'deployment_max_refund_paise':ceiling.max_refund_paise if ceiling else None,'window_basis':'razorpay_payment_created_at','window_boundary':'exclusive','timezone':'Asia/Kolkata'}


def read_policy(request: Request) -> dict[str,Any]:
    """Return policy history for the authenticated tenant and receipt the read."""
    gateway=request.app.state.gateway
    validate_headers(request)
    if request.query_params or request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding'):raise GatewayDenied('INVALID_REQUEST','policy.read',400)
    with Session(gateway.engine) as s,s.begin():
        reserve_audit_transaction(s)
        human=authenticate_operator(s,request,origin=gateway.settings.origin)
        result=policy_payload(s,gateway,human.tenant_id)
        result['history']=[{'id':r.id,'rules':r.rules,'created_by':r.created_by,'created_at':r.created_at} for r in s.scalars(select(RefundPolicyRevision).where(RefundPolicyRevision.tenant_id==human.tenant_id).order_by(RefundPolicyRevision.created_at.desc(),RefundPolicyRevision.id.desc()).limit(20))]
        gateway.audit(s,b'','REFUND_POLICY_READ','business.policy_read',True)
        return result


def save_policy(request: Request,body: PolicyUpdate) -> dict[str,Any]:
    """Atomically publish an audited revision; refuse edits during unresolved provider work."""
    gateway=request.app.state.gateway
    with Session(gateway.engine) as s,s.begin():
        reserve_audit_transaction(s)
        human=authenticate_operator(s,request,csrf=True,origin=gateway.settings.origin)
        lock_tenant_policy(s,human.tenant_id)
        head=s.get(BusinessRefundPolicy,human.tenant_id)
        if (head.revision_id if head else None)!=body.expected_revision:raise GatewayDenied('POLICY_EDIT_CONFLICT','business.policy_revision',409)
        if s.scalar(select(Operation.id).where(Operation.tenant_id==human.tenant_id,Operation.status=='PENDING').limit(1)):
            raise GatewayDenied('POLICY_OPERATIONS_PENDING','business.policy_activation',409)
        ceiling=gateway.policy.tenants.get(human.tenant_id)
        if ceiling is None:raise GatewayDenied('TENANT_OUT_OF_SCOPE','business.policy_scope')
        if body.rules.max_refund_paise is not None and body.rules.max_refund_paise>ceiling.max_refund_paise:
            raise GatewayDenied('POLICY_EXCEEDS_DEPLOYMENT_LIMIT','business.policy_ceiling',400)
        identifier=str(uuid4());rules=body.rules.model_dump()
        row=RefundPolicyRevision(id=identifier,tenant_id=human.tenant_id,rules=rules,content_hash='sha256:'+hashlib.sha256(rfc8785.dumps(rules)).hexdigest(),created_by=human.operator_id,created_at=int(time.time()))
        s.add(row);s.flush()
        if head is None:s.add(BusinessRefundPolicy(tenant_id=human.tenant_id,revision_id=identifier))
        else:head.revision_id=identifier
        s.flush()
        result=policy_payload(s,gateway,human.tenant_id)
        gateway.audit(s,b'','REFUND_POLICY_UPDATED','business.policy_update',True)
        return result


def bounded(session: Session,statement: Any) -> list[Any]:
    """Fail explicitly on oversized periods instead of silently truncating business metrics."""
    rows=session.execute(statement.limit(LIMIT+1)).all()
    if len(rows)>LIMIT:raise GatewayDenied('ANALYTICS_RANGE_TOO_LARGE','analytics.limit',413)
    return rows


def analytics(request: Request) -> dict[str,Any]:
    """Aggregate full real rows for a bounded local-calendar period, without sample data."""
    gateway=request.app.state.gateway;validate_headers(request)
    if set(request.query_params)-{'days'} or len(request.query_params.getlist('days'))>1 or request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding'):raise GatewayDenied('INVALID_REQUEST','analytics.query',400)
    raw=request.query_params.get('days','30')
    if raw not in ('7','30','90'):raise GatewayDenied('INVALID_REQUEST','analytics.range',400)
    days=int(raw);now=int(time.time());end=datetime.fromtimestamp(now,TZ);start=end.replace(hour=0,minute=0,second=0,microsecond=0)-timedelta(days=days-1);since=int(start.timestamp())
    bins={(start+timedelta(days=i)).date().isoformat():{'date':(start+timedelta(days=i)).date().isoformat(),'completed_refunds':0,'refunded_paise':0,'proposals':0,'denied_decisions':0,'model_calls':0} for i in range(days)}
    with Session(gateway.engine) as s,s.begin():
        reserve_audit_transaction(s);human=authenticate_operator(s,request,origin=gateway.settings.origin);tenant=human.tenant_id
        payments=bounded(s,select(Payment.id,Order.paid_paise,Order.refunded_paise,Resource.payment_created_at).join(Order,Order.id==Payment.order_id).outerjoin(Resource,Resource.id==Payment.id).where(Payment.tenant_id==tenant,Order.tenant_id==tenant))
        ops=bounded(s,select(Operation.status,Operation.action,Operation.payment_id,Operation.created_at,Operation.reason).where(Operation.tenant_id==tenant,Operation.created_at>=since,Operation.created_at<=now))
        calls=bounded(s,select(ModelCall.model,ModelCall.outcome,ModelCall.latency_ms,ModelCall.total_tokens,ModelCall.created_at).where(ModelCall.tenant_id==tenant,ModelCall.created_at>=since,ModelCall.created_at<=now))
        decisions=bounded(s,select(Receipt.allowed,Receipt.reason,Receipt.rule_id,Receipt.timestamp).where(Receipt.tenant_id==tenant,or_(Receipt.action_digest.is_not(None),Receipt.reason.in_(['REFUND_WINDOW_EXPIRED','PAYMENT_DATE_UNAVAILABLE','PARTIAL_REFUND_NOT_ALLOWED','REFUND_LIMIT_EXCEEDED','INSUFFICIENT_REFUNDABLE','REFUND_IN_FLIGHT','STALE_RESOURCE','POLICY_CHANGED','DESTINATION_NOT_ORIGINAL','TOOL_NOT_ALLOWED'])),Receipt.timestamp>=since,Receipt.timestamp<=now))
        from intentlock.db import Proposal
        proposals=bounded(s,select(Proposal.created_at).where(Proposal.tenant_id==tenant,Proposal.created_at>=since,Proposal.created_at<=now))
        def day(timestamp:int) -> dict[str,Any]:return bins[datetime.fromtimestamp(timestamp,TZ).date().isoformat()]
        completed=0;amount=0;status=Counter();refund_payments=set()
        for state,action,payment_id,created,reason in ops:
            status[state]+=1
            if state=='DONE':
                value=action['args']['amount_paise']
                if type(value) is not int or not 0<value<=9007199254740991:raise ValueError('invalid ledger amount')
                completed+=1;amount+=value;refund_payments.add(payment_id)
                day(created)['completed_refunds']+=1;day(created)['refunded_paise']+=value
        for (created,) in proposals:day(created)['proposals']+=1
        reasons=Counter();allowed=0;denied=0
        for ok,reason,rule,created in decisions:
            if ok:allowed+=1
            else:denied+=1;reasons[(reason,rule)]+=1;day(created)['denied_decisions']+=1
        models=Counter();outcomes=Counter();latencies=[];tokens=0;known_tokens=0
        for model,outcome,latency,total,created in calls:
            models[model]+=1;outcomes[outcome]+=1;latencies.append(latency);day(created)['model_calls']+=1
            if total is not None:tokens+=total;known_tokens+=1
        latencies.sort()
        p95=latencies[max(0,(len(latencies)*95+99)//100-1)] if latencies else None
        if any(type(value) is not int or not 0<=value<=9007199254740991 for row in payments for value in (row.paid_paise,row.refunded_paise)):
            raise ValueError('invalid tracked money')
        tracked_paid=sum(r.paid_paise for r in payments);tracked_refunded=sum(r.refunded_paise for r in payments)
        if any(value>9007199254740991 for value in (tracked_paid,tracked_refunded,amount)):
            raise GatewayDenied('ANALYTICS_TOTAL_TOO_LARGE','analytics.safe_integer',413)
        missing_dates=sum(r.payment_created_at is None for r in payments)
        tickets=s.scalar(select(func.count()).select_from(Ticket).where(Ticket.tenant_id==tenant,Ticket.created_at>=since,Ticket.created_at<=now))
        undated_tickets=s.scalar(select(func.count()).select_from(Ticket).where(Ticket.tenant_id==tenant,Ticket.created_at.is_(None)))
        gateway.audit(s,b'','ANALYTICS_READ','analytics.tenant_scope',True)
        return {'timezone':'Asia/Kolkata','days':days,'start_at':since,'as_of':now,'currency':'INR','tracked':{'payments':len(payments),'paid_paise':tracked_paid,'refunded_paise':tracked_refunded,'refund_rate_bps':tracked_refunded*10000//tracked_paid if tracked_paid else None,'missing_payment_dates':missing_dates},'period':{'completed_refunds':completed,'refunded_paise':amount,'refunded_payments':len(refund_payments),'operations':len(ops),'tickets':tickets,'proposals':len(proposals),'allowed_decisions':allowed,'denied_decisions':denied,'model_calls':len(calls),'model_latency_p95_ms':p95,'known_total_tokens':tokens,'calls_with_token_usage':known_tokens},'daily':list(bins.values()),'operation_statuses':dict(status),'denial_reasons':[{'reason':reason,'rule_id':rule,'count':count} for (reason,rule),count in reasons.most_common(10)],'models':dict(models),'model_outcomes':dict(outcomes),'coverage':{'undated_historical_tickets':undated_tickets,'chart_attribution':'operation_created_at','scope':'Mapped payments only; current balances may include provider refunds outside IntentLock. Decisions are not unique refund requests.'}}


async def failure(request: Request,error: Exception) -> JSONResponse:
    """Receipt API denials without logging raw policies or customer data."""
    denied=error if isinstance(error,GatewayDenied) else GatewayDenied('INSIGHTS_UNAVAILABLE','insights.exception',503)
    body,status=await run_in_threadpool(request.app.state.gateway.deny,b'',denied,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(body,status_code=status)


@router.get('/v1/analytics')
async def get_analytics(request: Request) -> JSONResponse:
    """Read authenticated, tenant-scoped visual analytics."""
    try:return JSONResponse(await run_in_threadpool(analytics,request))
    except Exception as error:return await failure(request,error)


@router.get('/v1/refund-policy')
async def get_policy(request: Request) -> JSONResponse:
    """Read current business policy and its actual immutable revision history."""
    try:return JSONResponse(await run_in_threadpool(read_policy,request))
    except Exception as error:return await failure(request,error)


@router.put('/v1/refund-policy')
async def put_policy(request: Request) -> JSONResponse:
    """Publish strict, CSRF-protected business policy edits with optimistic concurrency."""
    try:
        validate_headers(request)
        if request.query_params or request.headers.get('content-type','').split(';')[0]!='application/json':raise GatewayDenied('INVALID_REQUEST','policy.request',400)
        raw=b''
        async for chunk in request.stream():
            raw+=chunk
            if len(raw)>4096:raise GatewayDenied('REQUEST_TOO_LARGE','policy.body',413)
        try:body=PolicyUpdate.model_validate(_load_json(raw))
        except (ValueError,TypeError):raise GatewayDenied('INVALID_REQUEST','policy.schema',400) from None
        return JSONResponse(await run_in_threadpool(save_policy,request,body))
    except Exception as error:return await failure(request,error)
