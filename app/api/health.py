"""Technical process/readiness probes; these never authorize a business action."""
from typing import Any
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from sqlalchemy import select,literal
from starlette.concurrency import run_in_threadpool
from app.core.receipts import load_receipt_key
from intentlock.db import ApprovalDispatch,Operation

router=APIRouter()


@router.get('/health/live')
async def live() -> dict[str,str]:
    """Report process liveness without credentials, tenant data or provider calls."""
    return {'status':'live'}


@router.get('/health/ready')
async def ready(request: Request) -> JSONResponse:
    """Check actual schema, audit-key availability and the authenticated executor link.

    Readiness is infrastructure state, not an authorization decision. No grant,
    refund, ticket, receipt or other business record is created by these probes.
    Provider availability and sufficient refund balance require separate live checks.
    """
    def check() -> dict[str,str]:
        gateway=getattr(request.app.state,'gateway',None)
        service=gateway if gateway is not None else request.app.state.service
        with service.engine.connect() as connection:
            connection.execute(select(literal(1)))
            connection.execute(select(Operation.id).limit(1))
            connection.execute(select(ApprovalDispatch.proposal_id).limit(1))
        load_receipt_key()
        if gateway is not None and gateway.executor is not None:
            result=gateway.executor.call('internal/health',{})
            if result!={'status':'ready'}:
                raise ValueError('executor readiness protocol mismatch')
        return {'status':'ready','component':'gateway' if gateway is not None else 'executor'}
    try:
        result=await run_in_threadpool(check)
        return JSONResponse(result,headers={'Cache-Control':'no-store'})
    except Exception:
        return JSONResponse({'status':'not_ready','reason':'READINESS_UNAVAILABLE'},status_code=503,headers={'Cache-Control':'no-store'})
