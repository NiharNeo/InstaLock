"""HTTP transport: all action errors fail closed and are audited."""
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from intentlock.config import Settings
from intentlock.db import Order, Receipt, Ticket, UsedGrant, User, engine_for
from intentlock.gateway import Denied, authenticate, check_action, execute, record_deny
from intentlock.schema import Action, Envelope, digest, parse_json

MAX_BODY = 65536

def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application without creating tables or importing business data."""
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings or Settings.from_env()
        app.state.engine = engine_for(app.state.settings.database_url)
        yield
        app.state.engine.dispose()
    app = FastAPI(title='IntentLock', lifespan=lifespan, docs_url=None, redoc_url=None)

    @app.middleware('http')
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.post('/api/execute')
    @app.post('/api/preview')
    async def action_request(request: Request) -> JSONResponse:
        """Validate, decide, and audit every request at an action boundary."""
        raw = b''
        envelope = None
        cfg = app.state.settings
        engine = app.state.engine
        try:
            async for chunk in request.stream():
                raw += chunk[:MAX_BODY + 1 - len(raw)]
                if len(raw) > MAX_BODY:
                    raise Denied('REQUEST_TOO_LARGE')
            if any(len(request.headers.getlist(name)) > 1 for name in ('authorization', 'content-type')):
                raise Denied('AMBIGUOUS_HEADERS')
            preview = request.url.path.endswith('/preview')
            authenticate(request.headers.get('authorization'), cfg.operator_token if preview else cfg.agent_token)
            if request.headers.get('content-type', '').split(';')[0] != 'application/json':
                raise Denied('INVALID_CONTENT_TYPE')
            data = parse_json(raw)
            if preview:
                action = Action.model_validate(data)
                with Session(engine) as session, session.begin():
                    check_action(session, action, cfg)
                    # A successful preview is informational, never execution consent.
                    from intentlock.gateway import receipt
                    audit = receipt(session, cfg, raw, 'PREVIEW_VALID', allowed=True, proposed=action)
                return JSONResponse({'action': action.model_dump(), 'action_digest': digest(action), 'policy_version': cfg.policy_version, 'receipt': audit})
            envelope = Envelope.model_validate(data)
            return JSONResponse(await run_in_threadpool(execute, engine, cfg, raw, envelope))
        except Denied as exc:
            reason = exc.reason
        except (ValidationError, ValueError, TypeError, UnicodeError, RecursionError):
            reason = 'INVALID_REQUEST'
        except Exception:
            reason = 'INTERNAL_ERROR'
        try:
            result = record_deny(engine, cfg, raw, reason, envelope)
            return JSONResponse(result, status_code=401 if reason == 'UNAUTHENTICATED' else 403)
        except Exception:
            return JSONResponse({'allowed': False, 'reason': 'AUDIT_UNAVAILABLE', 'rule_id': 'audit.required', 'policy_version': cfg.policy_version}, status_code=503)

    @app.get('/api/agent/context')
    def agent_context(request: Request) -> JSONResponse:
        """Expose only this agent tenant's orders and untrusted tickets."""
        cfg = app.state.settings
        try:
            authenticate(request.headers.get('authorization'), cfg.agent_token)
            with Session(app.state.engine) as session:
                def rows(model: Any) -> list[dict[str, Any]]:
                    return [{column.name: getattr(row, column.name) for column in model.__table__.columns} for row in session.scalars(select(model).where(model.tenant_id == cfg.agent_tenant).order_by(model.id).limit(200))]
                return JSONResponse({'orders': rows(Order), 'tickets': rows(Ticket)})
        except Denied:
            return JSONResponse({'reason': 'UNAUTHENTICATED'}, status_code=401)
        except Exception:
            return JSONResponse({'reason': 'DATABASE_UNAVAILABLE'}, status_code=503)

    @app.get('/api/state')
    def state(request: Request) -> JSONResponse:
        """Read operator-visible records and the latest bounded decision trail."""
        cfg = app.state.settings
        try:
            authenticate(request.headers.get('authorization'), cfg.operator_token)
        except Denied:
            return JSONResponse({'reason': 'UNAUTHENTICATED'}, status_code=401)
        try:
            with Session(app.state.engine) as session:
                def rows(model: Any) -> list[dict[str, Any]]:
                    return [{column.name: getattr(row, column.name) for column in model.__table__.columns} for row in session.scalars(select(model).limit(200))]
                return JSONResponse({'orders': rows(Order), 'tickets': rows(Ticket), 'users': rows(User), 'grants': rows(UsedGrant), 'receipts': [{column.name: getattr(row, column.name) for column in Receipt.__table__.columns} for row in session.scalars(select(Receipt).order_by(Receipt.timestamp.desc(), Receipt.id).limit(200))]})
        except Exception:
            return JSONResponse({'reason': 'DATABASE_UNAVAILABLE'}, status_code=503)
    return app

app = create_app()
