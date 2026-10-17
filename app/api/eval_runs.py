"""Operator-only tenant-scoped evaluation history for the Stitch Metrics page."""
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, load_only
from starlette.concurrency import run_in_threadpool
from app.auth.service import authenticate_operator
from app.core.errors import GatewayDenied
from intentlock.db import EvalRun

router=APIRouter()


def serialize(row: EvalRun,*,detail: bool = False) -> dict[str,Any]:
    """Return persisted evidence, excluding capture artifacts and credential material."""
    result={'id':row.id,'tenant_id':row.tenant_id,'git_sha':row.git_sha,'started_at':row.started_at,'finished_at':row.finished_at,'status':row.status,'summary':row.summary}
    if detail:
        result['cases']=row.cases
    return result


def read(request: Request,identifier: str | None) -> dict[str,Any]:
    """Authenticate first, enforce tenant from session, validate bounded pagination."""
    gateway=request.app.state.gateway
    if any(len(request.headers.getlist(h))>1 for h in ('authorization','cookie','origin')):
        raise GatewayDenied('AMBIGUOUS_HEADERS','eval.history',400)
    if request.headers.get('content-length') not in (None,'0') or request.headers.get('transfer-encoding'):
        raise GatewayDenied('INVALID_REQUEST','eval.read_body',400)
    allowed=set() if identifier else {'limit','cursor','status'}
    params=request.query_params
    if set(params)-allowed or any(len(params.getlist(k))!=1 for k in params):
        raise GatewayDenied('INVALID_REQUEST','eval.query',400)
    with Session(gateway.engine) as session,session.begin():
        human=authenticate_operator(session,request,origin=gateway.settings.origin)
        if identifier:
            row=session.get(EvalRun,identifier)
            if row is None or row.tenant_id!=human.tenant_id:
                raise GatewayDenied('EVAL_RUN_NOT_FOUND','eval.tenant_scope',404)
            receipt=gateway.audit(session,b'','EVAL_RUN_READ','eval.history',True)
            return {**serialize(row,detail=True),'receipt_id':receipt}
        limit=params.get('limit','20')
        if not limit.isascii() or not limit.isdigit() or len(limit)>3 or not 1<=int(limit)<=100:
            raise GatewayDenied('INVALID_REQUEST','eval.pagination',400)
        status=params.get('status')
        if status is not None and status not in {'RUNNING','PASS','FAIL','BLOCKED','INCOMPLETE','INCONCLUSIVE'}:
            raise GatewayDenied('INVALID_REQUEST','eval.status',400)
        statement=select(EvalRun).options(load_only(EvalRun.id,EvalRun.tenant_id,EvalRun.git_sha,EvalRun.started_at,EvalRun.finished_at,EvalRun.status,EvalRun.summary,raiseload=True)).where(EvalRun.tenant_id==human.tenant_id)
        if status:
            statement=statement.where(EvalRun.status==status)
        if params.get('cursor'):
            cursor=session.scalar(select(EvalRun).options(load_only(EvalRun.id,EvalRun.tenant_id,EvalRun.started_at,raiseload=True)).where(EvalRun.id==params['cursor'],EvalRun.tenant_id==human.tenant_id))
            if cursor is None or cursor.tenant_id!=human.tenant_id:
                raise GatewayDenied('INVALID_REQUEST','eval.cursor',400)
            statement=statement.where(or_(EvalRun.started_at<cursor.started_at,(EvalRun.started_at==cursor.started_at)&(EvalRun.id<cursor.id)))
        receipt=gateway.audit(session,b'','EVAL_RUNS_READ','eval.history',True)
        rows=list(session.scalars(statement.order_by(EvalRun.started_at.desc(),EvalRun.id.desc()).limit(int(limit)+1)))
        return {'tenant_id':human.tenant_id,'execution_mode':'trusted-executor' if gateway.executor is not None else 'ledger-reference','policy_version':gateway.policy.policy_version,'provider_timing':'monotonic-real-provider-spans-v1' if gateway.executor is not None else None,'items':[serialize(row) for row in rows[:int(limit)]],'next_cursor':rows[int(limit)-1].id if len(rows)>int(limit) else None,'receipt_id':receipt}


async def dispatch(request: Request,identifier: str | None = None) -> JSONResponse:
    """Keep errors stable and signed; do not expose another tenant's history."""
    try:
        return JSONResponse(await run_in_threadpool(read,request,identifier))
    except GatewayDenied as error:
        failure=error
    except Exception:
        failure=GatewayDenied('AUDIT_UNAVAILABLE','eval.history',503)
    result,status=await run_in_threadpool(request.app.state.gateway.deny,b'',failure,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(result,status_code=status)


@router.get('/v1/eval-runs')
async def runs(request: Request) -> JSONResponse:
    """List actual evaluation runs for the authenticated operator's tenant."""
    return await dispatch(request)


@router.get('/v1/eval-runs/{run_id}')
async def run_detail(request: Request,run_id: str) -> JSONResponse:
    """Return sanitized per-case evidence for one same-tenant live evaluation."""
    return await dispatch(request,run_id)
