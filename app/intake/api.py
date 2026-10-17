"""Size-bounded public support endpoint; never returns raw ticket contents."""
from typing import Any
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from intentlock.schema import parse_json
from app.core.errors import GatewayDenied
from app.intake.service import MAX_BODY, TicketInput, create_ticket, rate_limit

router=APIRouter()


@router.post('/public/tickets')
async def intake(request: Request) -> JSONResponse:
    """Rate-limit before parsing and storing a bounded customer submission."""
    gateway=request.app.state.gateway
    raw=b''
    try:
        def count() -> None:
            with Session(gateway.engine) as session,session.begin():
                if request.client is None:
                    raise GatewayDenied('INTAKE_CLIENT_UNAVAILABLE','intake.client',503)
                rate_limit(session,request.client.host)
        await run_in_threadpool(count)
        if request.query_params or any(len(request.headers.getlist(h))>1 for h in ('content-type','content-length')):
            raise GatewayDenied('INVALID_REQUEST','intake.headers',400)
        if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/json':
            raise GatewayDenied('INVALID_CONTENT_TYPE','intake.json',415)
        async for chunk in request.stream():
            raw+=chunk[:MAX_BODY+1-len(raw)]
            if len(raw)>MAX_BODY:
                raise GatewayDenied('REQUEST_TOO_LARGE','intake.body_limit',413)
        body=TicketInput.model_validate(parse_json(raw))
        def save() -> dict[str,Any]:
            with Session(gateway.engine) as session,session.begin():
                return create_ticket(session,body,gateway.policy.policy_version)
        return JSONResponse(await run_in_threadpool(save),status_code=202)
    except GatewayDenied as error:
        failure=error
    except (ValueError,TypeError):
        failure=GatewayDenied('INVALID_REQUEST','intake.schema',400)
    except Exception:
        failure=GatewayDenied('INTAKE_UNAVAILABLE','intake.exception',503)
    result,status=await run_in_threadpool(gateway.deny,raw,failure)
    return JSONResponse(result,status_code=status,headers={'Retry-After':'60'} if status==429 else None)
