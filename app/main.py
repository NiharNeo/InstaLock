"""Production v1 gateway entrypoint; no legacy credential routes are mounted."""
from contextlib import asynccontextmanager
import time
from typing import Any, AsyncIterator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from app.adapters.payments import DatabasePaymentAdapter, ResourceAdapter
from app.intake.api import router as intake_router
from app.agent.api import router as agent_router
from app.api.eval_runs import router as eval_router
from app.api.receipts import router as receipts_router
from app.core.receipts import load_receipt_key
from app.api.gateway import Gateway
from app.executor.client import ExecutorClient
from app.config import GatewaySettings
from app.auth.service import SESSION_COOKIE
from app.core.canonical import _load_json
from app.core.errors import GatewayDenied
from app.core.grants import GrantIssueError, GrantSettings
from app.core.orchestrator import RefundOrchestrator
from app.core.policy import PolicyEngine
from intentlock.db import engine_for

MAX_BODY = 65536


def create_app(settings: GatewaySettings | None = None, *, adapter: ResourceAdapter | None = None, orchestrator: RefundOrchestrator | None = None) -> FastAPI:
    """Load one immutable policy at startup, bind real components, and deny errors."""
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        config = settings or GatewaySettings.from_env()
        load_receipt_key()
        policy = PolicyEngine.load(config.policy_file)
        GrantSettings(issuer=config.issuer,policy_version=policy.policy_version)
        engine = engine_for(config.database_url)
        remote=ExecutorClient(config.executor_url,config.executor_token) if config.executor_url and config.executor_token else None
        app.state.gateway = Gateway(engine,config,policy,adapter or remote or DatabasePaymentAdapter(),orchestrator or RefundOrchestrator())
        app.state.gateway.executor=remote
        try:
            yield
        finally:
            if remote:
                remote.client.close()
            engine.dispose()

    app = FastAPI(title='IntentLock v1',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)

    app.include_router(receipts_router)
    app.include_router(eval_router)
    app.include_router(intake_router)
    app.include_router(agent_router)

    @app.middleware('http')
    async def response_security(request: Request, call_next: Any) -> Any:
        started=time.perf_counter_ns()
        response = await call_next(request)
        total=time.perf_counter_ns()-started
        has_provider="X-IntentLock-Provider-Ns" in response.headers
        provider=int(response.headers.get("X-IntentLock-Provider-Ns","0"))
        response.headers["X-IntentLock-Gateway-Ns"]=str(total)
        response.headers["X-IntentLock-Provider-Ns"]=str(provider)
        response.headers["X-IntentLock-Timing-Valid"]="1" if 0<=provider<=total and (request.url.path!="/v1/execute" or has_provider) else "0"
        response.headers["Server-Timing"]=f"gateway_path;dur={total/1000000:.6f}, provider_io;dur={provider/1000000:.6f}"
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    async def dispatch(request: Request, operation: str, proposal_id: str | None = None) -> JSONResponse:
        gateway = app.state.gateway
        raw = b''
        try:
            if any(len(request.headers.getlist(name)) > 1 for name in ('authorization','content-type','cookie','x-csrf-token','idempotency-key','origin')):
                raise GatewayDenied('AMBIGUOUS_HEADERS','http.single_headers',400)
            if request.query_params:
                raise GatewayDenied('INVALID_REQUEST','http.no_query_parameters',400)
            async for chunk in request.stream():
                raw += chunk[:MAX_BODY + 1 - len(raw)]
                if len(raw) > MAX_BODY:
                    raise GatewayDenied('REQUEST_TOO_LARGE','http.body_limit',413)
            if raw or operation not in {'approve','preview','logout'}:
                if request.headers.get('content-type','').split(';')[0].strip().lower() != 'application/json':
                    raise GatewayDenied('INVALID_CONTENT_TYPE','http.json_only',415)
            data = _load_json(raw) if raw else {}
            if operation == 'preview' and raw:
                raise GatewayDenied('INVALID_REQUEST','http.read_body',400)
            def handle() -> dict[str,Any]:
                if operation == 'login':
                    return gateway.login(request,raw,data)
                if operation == 'logout':
                    if type(data) is not dict or data:
                        raise GatewayDenied('INVALID_REQUEST','schema.empty_logout',400)
                    return gateway.logout(request,raw)
                if operation == 'submit':
                    return gateway.submit(request,raw,data)
                if operation == 'execute':
                    return gateway.execute(request,raw,data)
                assert proposal_id is not None
                if operation == 'preview':
                    return gateway.preview(request,raw,proposal_id)
                return gateway.approve(request,raw,proposal_id,data)
            result = await run_in_threadpool(handle)
            cookie_token = result.pop('_cookie_token',None)
            cookie_max_age = result.pop('_cookie_max_age',None)
            provider_ns=result.pop('_provider_ns',0)
            if type(provider_ns) is not int or provider_ns<0:
                raise GatewayDenied('INVALID_TIMING','executor.protocol',503)
            response = JSONResponse(result,status_code=result.pop('_http_status',201 if operation == 'submit' else 200))
            response.headers['X-IntentLock-Provider-Ns']=str(provider_ns)
            if operation == 'login':
                response.set_cookie(SESSION_COOKIE,cookie_token,max_age=cookie_max_age,path='/v1',httponly=True,secure=gateway.settings.origin.startswith('https://'),samesite='strict')
            elif operation == 'logout':
                response.delete_cookie(SESSION_COOKIE,path='/v1',httponly=True,secure=gateway.settings.origin.startswith('https://'),samesite='strict')
            return response
        except GatewayDenied as exc:
            failure = exc
        except GrantIssueError as exc:
            failure = GatewayDenied(exc.reason.value,'grant.'+exc.reason.value.lower(),503 if exc.reason.value in {'AUDIT_UNAVAILABLE','INTERNAL_ERROR'} else 403)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            failure = GatewayDenied('INVALID_REQUEST','schema.strict',400)
        except Exception:
            failure = GatewayDenied('INTERNAL_ERROR','gateway.exception',503)
        result,status = await run_in_threadpool(gateway.deny,raw,failure,getattr(request.state,"receipt_tenant",None),getattr(request.state,"receipt_actor",None))
        return JSONResponse(result,status_code=status)

    @app.post('/v1/session')
    async def login(request: Request) -> JSONResponse:
        """Authenticate an existing human session secret; agent keys never work here."""
        return await dispatch(request,'login')

    @app.delete('/v1/session')
    async def logout(request: Request) -> JSONResponse:
        """Revoke the authenticated human session with CSRF protection."""
        return await dispatch(request,'logout')

    @app.post('/v1/proposals')
    async def proposals(request: Request) -> JSONResponse:
        """Accept only a tenant/actor-bound agent key and a strict ProposedAction."""
        return await dispatch(request,'submit')

    @app.get('/v1/proposals/{proposal_id}/preview')
    async def preview(request: Request, proposal_id: str) -> JSONResponse:
        """Return a trusted live effect and record the human session's review."""
        return await dispatch(request,'preview',proposal_id)

    @app.post('/v1/proposals/{proposal_id}/approve')
    async def approve(request: Request, proposal_id: str) -> JSONResponse:
        """Require a human session and CSRF; never take a client action digest."""
        return await dispatch(request,'approve',proposal_id)

    @app.post('/v1/execute')
    async def execute(request: Request) -> JSONResponse:
        """Run grant verification, deterministic policy, and an atomic refund."""
        return await dispatch(request,'execute')

    @app.exception_handler(HTTPException)
    async def unhandled_route(request: Request, exception: HTTPException) -> JSONResponse:
        """Keep unsupported route/method denials stable and auditable too."""
        result,status = await run_in_threadpool(app.state.gateway.deny,b'',GatewayDenied('ENDPOINT_NOT_ALLOWED','http.route',exception.status_code))
        return JSONResponse(result,status_code=status)
    return app


app = create_app()
