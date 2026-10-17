"""Tenant-scoped business workspace and provider setup requests; no credentials returned."""
import time
from typing import Any
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.auth.service import authenticate_operator
from app.core.canonical import _load_json
from app.core.errors import GatewayDenied
from app.core.business_policy import effective_policy
from app.core.receipts import reserve_audit_transaction
from intentlock.db import IntegrationRequest,Order,Payment,Resource,WebhookEvent

router=APIRouter()


def read_workspace(request: Request) -> dict[str,Any]:
    """Read actual mapped payments and provider status for the authenticated business."""
    gateway=request.app.state.gateway
    if request.query_params or request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding') or any(len(request.headers.getlist(h))>1 for h in ('cookie','origin','authorization')):
        raise GatewayDenied('INVALID_REQUEST','business.request',400)
    with Session(gateway.engine) as session,session.begin():
        reserve_audit_transaction(session)
        human=authenticate_operator(session,request,origin=gateway.settings.origin)
        rows=session.execute(select(Payment,Order,Resource).join(Order,Order.id==Payment.order_id).outerjoin(Resource,Resource.id==Payment.id).where(Payment.tenant_id==human.tenant_id,Order.tenant_id==human.tenant_id).order_by(Payment.id.desc()).limit(100)).all()
        events=session.scalar(select(func.count()).select_from(WebhookEvent).where(WebhookEvent.tenant_id==human.tenant_id))
        setup=session.get(IntegrationRequest,(human.tenant_id,'razorpay'))
        gateway.audit(session,b'','BUSINESS_WORKSPACE_READ','business.tenant_scope',True)
        result={'tenant_id':human.tenant_id,'policy_version':effective_policy(session,gateway.policy,human.tenant_id).policy_version,'payments':[{'id':p.id,'order_id':o.id,'paid_paise':o.paid_paise,'refunded_paise':o.refunded_paise,'remaining_paise':o.paid_paise-o.refunded_paise,'currency':o.currency,'version':o.version,'status':r.status if r else 'NOT_SYNCED','synced_at':r.synced_at if r else None} for p,o,r in rows],'verified_webhook_events':events,'setup_request':{'status':setup.status,'created_at':setup.created_at} if setup else None}
    connection={'provider':'razorpay','status':'NOT_CONFIGURED','mode':None,'account_id':None}
    if gateway.executor:
        try:
            value=gateway.executor.call('internal/integrations/status',{'tenant_id':human.tenant_id})
            if value.get('provider')!='razorpay' or value.get('tenant_id')!=human.tenant_id or value.get('mode')!='test' or type(value.get('account_id')) is not str:raise ValueError('invalid provider status')
            connection={key:value[key] for key in ('provider','status','mode','account_id')}
        except Exception:
            connection['status']='UNAVAILABLE'
    result['connection']=connection
    return result


@router.get('/v1/business')
async def business(request: Request) -> JSONResponse:
    """Return business data from real tenant mappings and an authenticated executor."""
    try:return JSONResponse(await run_in_threadpool(read_workspace,request))
    except GatewayDenied as error:failure=error
    except Exception:failure=GatewayDenied('BUSINESS_WORKSPACE_UNAVAILABLE','business.read',503)
    body,status=await run_in_threadpool(request.app.state.gateway.deny,b'',failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(body,status_code=status)


@router.post('/v1/integrations/razorpay/request')
async def request_integration(request: Request) -> JSONResponse:
    """Persist a real setup request; never pretend this grants merchant API access."""
    gateway=request.app.state.gateway
    try:
        if request.query_params or any(len(request.headers.getlist(h))>1 for h in ('cookie','origin','authorization','x-csrf-token','content-type')):raise ValueError('ambiguous request')
        if request.headers.get('content-type','').split(';')[0]!='application/json':raise ValueError('JSON required')
        raw=b''
        async for chunk in request.stream():
            raw+=chunk
            if len(raw)>1024:raise ValueError('body limit')
        if _load_json(raw)!={}:raise ValueError('empty object required')
        def save() -> dict[str,Any]:
            with Session(gateway.engine) as session,session.begin():
                reserve_audit_transaction(session)
                human=authenticate_operator(session,request,csrf=True,origin=gateway.settings.origin)
                # Serialize repeated requests without changing another tenant's setup.
                from intentlock.db import User
                from sqlalchemy import update
                session.execute(update(User).where(User.id==human.operator_id).values(active=User.active))
                row=session.get(IntegrationRequest,(human.tenant_id,'razorpay'))
                if row is None:
                    row=IntegrationRequest(tenant_id=human.tenant_id,provider='razorpay',requested_by=human.operator_id,status='AWAITING_CONFIGURATION',created_at=int(time.time()))
                    session.add(row)
                gateway.audit(session,b'','INTEGRATION_SETUP_REQUESTED','integrations.human_request',True)
                return {'status':row.status,'provider':row.provider,'created_at':row.created_at}
        return JSONResponse(await run_in_threadpool(save),status_code=202)
    except GatewayDenied as error:failure=error
    except (ValueError,TypeError):failure=GatewayDenied('INVALID_REQUEST','business.schema',400)
    except Exception:failure=GatewayDenied('INTEGRATION_REQUEST_UNAVAILABLE','business.integration',503)
    body,status=await run_in_threadpool(gateway.deny,b'',failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(body,status_code=status)
