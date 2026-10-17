"""Human-session-authenticated, tenant-scoped receipt inspection endpoints."""
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.auth.service import authenticate_operator
from app.core.errors import GatewayDenied
from app.core.receipts import append_receipt, serialize_receipt, verify_chain
from intentlock.db import Receipt

router=APIRouter()


def read_receipts(request: Request, verify: bool) -> dict[str,Any]:
    """Authenticate before filtering; tenant selection never comes from the caller."""
    gateway=request.app.state.gateway
    if any(len(request.headers.getlist(name))>1 for name in ('authorization','cookie','origin')):
        raise GatewayDenied('AMBIGUOUS_HEADERS','http.single_headers',400)
    if request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding'):
        raise GatewayDenied('INVALID_REQUEST','http.read_body',400)
    params=request.query_params
    allowed=set() if verify else {'after_seq','limit','decision','reason','snapshot_seq'}
    if set(params)-allowed or any(len(params.getlist(name))!=1 for name in params):
        raise GatewayDenied('INVALID_REQUEST','receipts.query',400)
    with Session(gateway.engine) as session,session.begin():
        human=authenticate_operator(session,request,origin=gateway.settings.origin)
        if verify:
            result=verify_chain(session,human.tenant_id)
            # Never append over a broken tail or hide the first broken link.
            if result['valid']:
                receipt_id=gateway.audit(session,b'','RECEIPT_CHAIN_VERIFIED','receipts.verify',True)
            else:
                # Audit the failed verification in the separate unscoped system
                # chain so a damaged tenant chain cannot prevent reporting it.
                from uuid import uuid4
                import hashlib
                import time
                row=append_receipt(session,tenant_id=None,actor_id=human.operator_id,id=str(uuid4()),timestamp=int(time.time()),allowed=False,reason='RECEIPT_CHAIN_BROKEN',rule_id='receipts.verify',policy_version=gateway.policy.policy_version,input_hash=hashlib.sha256(b'').hexdigest(),action_digest=None,request_id=None,refund_id=None,_system=True)
                receipt_id=row.id
            return {**result,'tenant_id':human.tenant_id,'first_broken_receipt_id':result.get('receipt_id') if not result['valid'] else None,'receipt_id':receipt_id}
        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            raw=params.get(name,str(default))
            if len(raw)>16 or not raw.isascii() or not raw.isdigit() or not minimum<=int(raw)<=maximum:
                raise GatewayDenied('INVALID_REQUEST','receipts.pagination',400)
            return int(raw)
        after=integer('after_seq',0,0,9007199254740991)
        limit=integer('limit',50,1,200)
        decision=params.get('decision')
        reason=params.get('reason')
        if decision is not None and decision not in {'ALLOW','DENY'}:
            raise GatewayDenied('INVALID_REQUEST','receipts.decision_filter',400)
        if reason is not None and (not reason or len(reason)>64 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in reason)):
            raise GatewayDenied('INVALID_REQUEST','receipts.reason_filter',400)
        statement=select(Receipt).where(Receipt.tenant_id==human.tenant_id,Receipt.seq>after)
        if decision is not None:
            statement=statement.where(Receipt.decision==decision)
        if reason is not None:
            statement=statement.where(Receipt.reason_code==reason)
        # Write audit before reading rows: acquire the SQLite writer once, avoid
        # read-upgrade races. Exclude this inspection's audit from the page.
        audit_id=gateway.audit(session,b'','RECEIPTS_READ','receipts.read',True)
        audit_row=session.get(Receipt,audit_id)
        assert audit_row is not None and audit_row.seq is not None
        snapshot=integer('snapshot_seq',audit_row.seq-1,0,audit_row.seq-1)
        rows=list(session.scalars(statement.where(Receipt.seq<=snapshot).order_by(Receipt.seq).limit(limit+1)))
        page=rows[:limit]
        return {'items':[serialize_receipt(row) for row in page],'next_after_seq':page[-1].seq if len(rows)>limit else None,'snapshot_seq':snapshot,'receipt_id':audit_id}


async def dispatch(request: Request, verify: bool) -> JSONResponse:
    """Return stable audited failures and never expose another tenant's records."""
    try:
        return JSONResponse(await run_in_threadpool(read_receipts,request,verify))
    except GatewayDenied as error:
        failure=error
    except Exception:
        failure=GatewayDenied('AUDIT_UNAVAILABLE','receipts.persistence',503)
    result,status=await run_in_threadpool(request.app.state.gateway.deny,b'',failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(result,status_code=status)


@router.get('/v1/receipts')
async def receipts(request: Request) -> JSONResponse:
    """List authenticated tenant receipts by exclusive sequence cursor and filters."""
    return await dispatch(request,False)


@router.get('/v1/receipts/verify')
async def verify_receipts(request: Request) -> JSONResponse:
    """Report the first broken sequence, link, payload hash, signature or head."""
    return await dispatch(request,True)
