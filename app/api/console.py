"""Bounded database-backed operator console with no service or grant credentials."""
from typing import Any
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.auth.service import authenticate_operator,session_csrf
from app.core.errors import GatewayDenied
from intentlock.db import ApprovalDispatch,ModelCall,Operation,Proposal,SupportChannel,Ticket

router=APIRouter()


def read_console(request: Request) -> dict[str,Any]:
    """Return the latest 50 real rows per section, strictly within the session tenant."""
    gateway=request.app.state.gateway
    if request.query_params or any(len(request.headers.getlist(name))>1 for name in ('cookie','authorization','origin')) or request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding'):
        raise GatewayDenied('INVALID_REQUEST','console.request',400)
    with Session(gateway.engine) as session,session.begin():
        human=authenticate_operator(session,request,origin=gateway.settings.origin)
        tenant=human.tenant_id
        receipt=gateway.audit(session,b'','CONSOLE_READ','console.tenant_scope',True)
        tickets=list(session.scalars(select(Ticket).where(Ticket.tenant_id==tenant).order_by(Ticket.id.desc()).limit(50)))
        proposals=list(session.scalars(select(Proposal).where(Proposal.tenant_id==tenant).order_by(Proposal.created_at.desc(),Proposal.id.desc()).limit(50)))
        operations=list(session.scalars(select(Operation).where(Operation.tenant_id==tenant).order_by(Operation.created_at.desc(),Operation.id.desc()).limit(50)))
        calls=list(session.scalars(select(ModelCall).where(ModelCall.tenant_id==tenant).order_by(ModelCall.created_at.desc(),ModelCall.id.desc()).limit(10)))
        channels=list(session.scalars(select(SupportChannel.id).where(SupportChannel.tenant_id==tenant,SupportChannel.active.is_(True)).order_by(SupportChannel.id).limit(50)))
        jobs=list(session.scalars(select(ApprovalDispatch).where(ApprovalDispatch.tenant_id==tenant).order_by(ApprovalDispatch.created_at.desc()).limit(50)))
        return {'operator_id':human.operator_id,'tenant_id':tenant,'policy_version':gateway.policy.policy_version,'receipt_id':receipt,'limit_per_section':50,'tickets':[{'id':r.id,'order_id':r.order_id,'status':r.processing_status,'redacted_excerpt':(r.redacted_text or '')[:500]} for r in tickets],'proposals':[{'id':r.id,'status':r.status,'action':r.action,'created_at':r.created_at} for r in proposals],'operations':[{'id':r.id,'proposal_id':r.proposal_id,'payment_id':r.payment_id,'amount_paise':r.action['args']['amount_paise'],'status':r.status,'reason':r.reason,'refund_id':r.provider_refund_id,'updated_at':r.updated_at} for r in operations],'model_calls':[{'ticket_id':r.ticket_id,'model':r.model,'outcome':r.outcome,'latency_ms':r.latency_ms,'created_at':r.created_at} for r in calls],'channels':channels,'dispatches':[{'proposal_id':r.proposal_id,'status':r.status,'reason':r.reason,'operation_id':r.operation_id} for r in jobs]}


@router.get('/v1/console')
async def console(request: Request) -> JSONResponse:
    """Read operator workflow state; exceptions fail closed and write signed denials."""
    try:
        return JSONResponse(await run_in_threadpool(read_console,request))
    except GatewayDenied as error:
        failure=error
    except Exception:
        failure=GatewayDenied('CONSOLE_UNAVAILABLE','console.read',503)
    body,status=await run_in_threadpool(request.app.state.gateway.deny,b'',failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(body,status_code=status)


@router.get('/v1/session')
async def session_context(request: Request) -> JSONResponse:
    """Resume an existing HttpOnly human session and supply its CSRF token to same-origin UI."""
    gateway=request.app.state.gateway
    try:
        if request.query_params or any(len(request.headers.getlist(name))>1 for name in ('cookie','authorization','origin')) or request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding'):
            raise GatewayDenied('INVALID_REQUEST','session.context',400)
        def read() -> dict[str,Any]:
            with Session(gateway.engine) as session,session.begin():
                human=authenticate_operator(session,request,origin=gateway.settings.origin)
                try:
                    csrf_token=session_csrf(human.session_id)
                except (KeyError,ValueError):
                    raise GatewayDenied('SESSION_CONTEXT_UNAVAILABLE','session.context',503) from None
                receipt=gateway.audit(session,b'','SESSION_RESUMED','session.context',True)
                return {'operator_id':human.operator_id,'tenant_id':human.tenant_id,'csrf_token':csrf_token,'receipt_id':receipt}
        return JSONResponse(await run_in_threadpool(read))
    except GatewayDenied as error:
        failure=error
    except Exception:
        failure=GatewayDenied('SESSION_CONTEXT_UNAVAILABLE','session.context',503)
    body,status=await run_in_threadpool(gateway.deny,b'',failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(body,status_code=status)
