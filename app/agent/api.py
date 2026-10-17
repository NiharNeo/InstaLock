"""Trusted narrow ticket/context and audit RPCs for the untrusted proposal worker."""
import time
from typing import Any
from uuid import uuid4
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select, update,func
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.agent.contracts import CallReport
from app.auth.service import authenticate_agent, authenticate_operator
from app.core.canonical import _Contract, _load_json
from app.core.errors import GatewayDenied, enforce
from app.intake.redaction import redact
from intentlock.db import ModelCall, Order, Payment, Ticket
from pydantic import Field

router=APIRouter()


class LinkTicket(_Contract):
    """Only an authenticated operator can repair an unlinked ticket association."""
    order_id: str = Field(min_length=1,max_length=128)


def claim(request: Request, data: Any) -> dict[str,Any]:
    """Lease one real ticket and return only re-redacted content and trusted state."""
    gateway=request.app.state.gateway
    if data!={}:
        raise GatewayDenied('INVALID_REQUEST','agent.empty_claim',400)
    with Session(gateway.engine) as session,session.begin():
        # Acquire the SQLite writer before identity/queue reads; portable no-op DML.
        session.execute(update(Ticket).where(Ticket.id=='').values(lease_until=Ticket.lease_until))
        identity=authenticate_agent(session,request)
        now=int(time.time())
        ticket=session.scalar(select(Ticket).join(Order,Order.id==Ticket.order_id).join(Payment,Payment.order_id==Order.id).where(Ticket.tenant_id==identity.tenant_id,Order.tenant_id==identity.tenant_id,Payment.tenant_id==identity.tenant_id,or_(Ticket.processing_status=='QUEUED',(Ticket.processing_status.in_(['PROCESSING','RETRY_WAIT']))&(Ticket.lease_until<=now))).order_by(Ticket.id).with_for_update(skip_locked=True).limit(1))
        if ticket is None:
            receipt=gateway.audit(session,b'','NO_TICKET_AVAILABLE','agent.queue',True)
            return {'ticket':None,'receipt_id':receipt}
        payment=session.scalar(select(Payment).where(Payment.order_id==ticket.order_id,Payment.tenant_id==identity.tenant_id))
        assert payment is not None
        snapshot=gateway.adapter.fetch(session,payment.id,identity.tenant_id)
        from app.core.business_policy import effective_policy
        policy=effective_policy(session,gateway.policy,identity.tenant_id)
        read_decision=policy.evaluate_read(scope='payment.read',tenant_id=identity.tenant_id,resource=snapshot)
        enforce(read_decision)
        ticket.redacted_text=redact(ticket.text)  # Also covers old imports and changed masking rules.
        ticket.claim_token=str(uuid4())
        ticket.claimed_by=identity.service_id
        ticket.lease_until=now+300
        ticket.processing_status='PROCESSING'
        receipt=gateway.audit(session,b'','TICKET_CLAIMED',read_decision.rule_id,True,request_id=ticket.id)
        config=policy.tenants[identity.tenant_id]
        from intentlock.db import StoreSupportRequest,StoreCheckout
        purchase_request=session.get(StoreSupportRequest,ticket.id)
        purchase=session.get(StoreCheckout,purchase_request.checkout_id) if purchase_request else None
        purchased_item=next((line for line in purchase.items if line['product_id']==purchase_request.product_id),None) if purchase and purchase.tenant_id==identity.tenant_id else None
        return {'ticket':{'ticket_id':ticket.id,'claim_token':ticket.claim_token,'redacted_text':ticket.redacted_text,'tenant_id':identity.tenant_id,'actor_id':identity.actor_id,'payment_id':snapshot.payment_id,'resource_ref':snapshot.order_id,'resource_version':snapshot.order_version,'remaining_refundable_paise':snapshot.remaining_refundable_paise,'payment_created_at':snapshot.payment_created_at,'current_time':now,'purchased_item':purchased_item,'requested_refund_paise':purchase_request.requested_paise if purchase_request else None,'refund_policy':{'refund_window_days':config.refund_window_days,'max_refund_paise':config.max_refund_paise,'partial_refunds':config.partial_refunds,'policy_version':policy.policy_version}},'receipt_id':receipt}


def report(request: Request, data: Any) -> dict[str,Any]:
    """Persist telemetry and a signed decision in one transaction, never model prose."""
    gateway=request.app.state.gateway
    body=CallReport.model_validate(data)
    with Session(gateway.engine) as session,session.begin():
        session.execute(update(Ticket).where(Ticket.id==body.ticket_id).values(lease_until=Ticket.lease_until))
        identity=authenticate_agent(session,request)
        ticket=session.get(Ticket,body.ticket_id)
        if ticket is None or ticket.tenant_id!=identity.tenant_id or ticket.claimed_by!=identity.service_id or ticket.claim_token!=body.claim_token:
            raise GatewayDenied('TICKET_CLAIM_MISMATCH','agent.claim')
        prior=session.scalar(select(ModelCall).where(ModelCall.claim_token==body.claim_token))
        if prior is not None:
            receipt=gateway.audit(session,b'','MODEL_REPORT_RETRY','agent.telemetry',True,request_id=ticket.id)
            return {'allowed':True,'reason':'MODEL_REPORT_RETRY','receipt_id':receipt}
        if ticket.processing_status!='PROCESSING' or ticket.lease_until is None or ticket.lease_until<=int(time.time()):
            raise GatewayDenied('TICKET_CLAIM_EXPIRED','agent.claim')
        session.add(ModelCall(id=str(uuid4()),tenant_id=identity.tenant_id,service_id=identity.service_id,created_at=int(time.time()),**body.model_dump()))
        ticket.processing_status={'PROPOSAL_SUBMITTED':'DONE','MODEL_ERROR':'MODEL_ERROR','SUBMISSION_UNCERTAIN':'REVIEW_REQUIRED'}.get(body.outcome,body.outcome)
        ticket.lease_until=None
        if body.outcome=='MODEL_ERROR':
            attempts=session.scalar(select(func.count()).select_from(ModelCall).where(ModelCall.ticket_id==ticket.id,ModelCall.outcome=='MODEL_ERROR'))
            if attempts<3:
                ticket.processing_status='RETRY_WAIT';ticket.lease_until=int(time.time())+30*(2**max(0,attempts-1))
        allowed=body.outcome=='PROPOSAL_SUBMITTED'
        receipt=gateway.audit(session,b'',body.outcome,'agent.model_result',allowed,request_id=ticket.id)
        return {'allowed':allowed,'reason':body.outcome,'receipt_id':receipt}


async def dispatch(request: Request, operation: str, ticket_id: str | None = None) -> JSONResponse:
    """Bound all agent RPC envelopes and route failures through the signed audit log."""
    gateway=request.app.state.gateway
    raw=b''
    try:
        if request.query_params or any(len(request.headers.getlist(h))>1 for h in ('authorization','cookie','content-type','x-csrf-token','origin')):
            raise GatewayDenied('INVALID_REQUEST','agent.headers',400)
        if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/json':
            raise GatewayDenied('INVALID_CONTENT_TYPE','agent.json',415)
        async for chunk in request.stream():
            raw+=chunk[:16385-len(raw)]
            if len(raw)>16384:
                raise GatewayDenied('REQUEST_TOO_LARGE','agent.body',413)
        data=_load_json(raw)
        def handle() -> dict[str,Any]:
            if operation=='claim':
                return claim(request,data)
            if operation=='report':
                return report(request,data)
            if operation=='retry':
                return retry_failed_ticket(request,ticket_id,data)
            body=LinkTicket.model_validate(data)
            with Session(gateway.engine) as session,session.begin():
                session.execute(update(Ticket).where(Ticket.id==ticket_id).values(lease_until=Ticket.lease_until))
                human=authenticate_operator(session,request,csrf=True,origin=gateway.settings.origin)
                ticket=session.get(Ticket,ticket_id)
                order=session.get(Order,body.order_id)
                if ticket is None or order is None or ticket.tenant_id!=human.tenant_id or order.tenant_id!=human.tenant_id:
                    raise GatewayDenied('RESOURCE_NOT_FOUND','ticket.link',404)
                if ticket.processing_status=='PROCESSING':
                    raise GatewayDenied('TICKET_IN_FLIGHT','ticket.link',409)
                ticket.order_id=order.id
                ticket.processing_status='QUEUED'
                receipt=gateway.audit(session,b'','TICKET_LINKED','ticket.link',True,request_id=ticket.id)
                return {'allowed':True,'reason':'TICKET_LINKED','receipt_id':receipt}
        return JSONResponse(await run_in_threadpool(handle))
    except GatewayDenied as error:
        failure=error
    except (ValueError,TypeError):
        failure=GatewayDenied('INVALID_REQUEST','agent.schema',400)
    except Exception:
        failure=GatewayDenied('INTERNAL_ERROR','agent.exception',503)
    result,status=await run_in_threadpool(gateway.deny,raw,failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(result,status_code=status)


@router.post('/v1/agent/tickets/claim')
async def claim_ticket(request: Request) -> JSONResponse:
    """Lease a redacted ticket with service-key authentication."""
    return await dispatch(request,'claim')


@router.post('/v1/agent/model-calls')
async def model_report(request: Request) -> JSONResponse:
    """Record bounded worker telemetry and invalid-proposal denials."""
    return await dispatch(request,'report')


@router.post('/v1/tickets/{ticket_id}/link')
async def link_ticket(request: Request,ticket_id: str) -> JSONResponse:
    """Require a human session and CSRF to associate an email/unlinked ticket."""
    return await dispatch(request,'link',ticket_id)


def retry_failed_ticket(request: Request,ticket_id: str | None,data: Any) -> dict[str,Any]:
    """Requeue failed model work only; existing proposals fence ambiguous resubmissions."""
    if data!={}:raise GatewayDenied('INVALID_REQUEST','ticket.empty_retry',400)
    from intentlock.db import Proposal
    gateway=request.app.state.gateway
    with Session(gateway.engine) as session,session.begin():
        session.execute(update(Ticket).where(Ticket.id==ticket_id).values(lease_until=Ticket.lease_until))
        human=authenticate_operator(session,request,csrf=True,origin=gateway.settings.origin)
        ticket=session.get(Ticket,ticket_id)
        if ticket is None or ticket.tenant_id!=human.tenant_id:raise GatewayDenied('RESOURCE_NOT_FOUND','ticket.scope',404)
        last=session.scalar(select(ModelCall).where(ModelCall.ticket_id==ticket.id).order_by(ModelCall.created_at.desc(),ModelCall.id.desc()).limit(1))
        if last is None or last.outcome!='MODEL_ERROR' or ticket.processing_status not in {'MODEL_ERROR','DONE','RETRY_WAIT'}:
            raise GatewayDenied('TICKET_NOT_RETRYABLE','ticket.retry_state',409)
        # Legacy MODEL_ERROR could follow a lost submit response. Refuse retry if
        # any proposal already exists for this order; never guess a missing reply.
        if session.scalar(select(Proposal.id).where(Proposal.tenant_id==human.tenant_id,Proposal.action['resource_ref'].as_string()==ticket.order_id).limit(1)):
            raise GatewayDenied('TICKET_REVIEW_REQUIRED','ticket.proposal_fence',409)
        ticket.processing_status='QUEUED';ticket.lease_until=None;ticket.claim_token=None;ticket.claimed_by=None
        receipt=gateway.audit(session,b'','TICKET_REQUEUED','ticket.retry_model',True,request_id=ticket.id)
        return {'allowed':True,'reason':'TICKET_REQUEUED','receipt_id':receipt}


@router.post('/v1/tickets/{ticket_id}/retry')
async def retry_ticket(request: Request,ticket_id: str) -> JSONResponse:
    """Require operator consent and CSRF to retry model processing, never a refund."""
    return await dispatch(request,'retry',ticket_id)
