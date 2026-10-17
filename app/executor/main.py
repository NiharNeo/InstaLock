"""Private executor RPC and public signature-authenticated Razorpay webhook."""
from contextlib import asynccontextmanager
import hashlib
import hmac
from typing import Any, AsyncIterator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.canonical import parse_action
from app.core.errors import GatewayDenied
from app.core.receipts import load_receipt_key
from app.core.timing import provider_spans, duration_ns
from app.core.policy import PolicyEngine
from app.executor.config import ExecutorSettings
from app.executor.models import RefundProvider
from app.executor.razorpay import RazorpayTestAdapter
from app.executor.service import ExecutorService
from intentlock.db import Payment, WebhookEvent, engine_for
from intentlock.schema import parse_json


def create_app(settings: ExecutorSettings | None = None, *, provider: RefundProvider | None = None) -> FastAPI:
    """Construct a credential-isolated executor; absent configuration fails startup."""
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        config=settings or ExecutorSettings.from_env()
        load_receipt_key()
        engine=engine_for(config.database_url)
        adapter=provider or RazorpayTestAdapter(config)
        app.state.service=ExecutorService(engine,config,PolicyEngine.load(config.policy_file),adapter)
        try:
            yield
        finally:
            if isinstance(adapter,RazorpayTestAdapter):
                adapter.close()
            engine.dispose()
    app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None,redirect_slashes=False)

    @app.exception_handler(HTTPException)
    async def rejected_route(request: Request, error: HTTPException) -> JSONResponse:
        """Audit unsupported methods and paths instead of bypassing receipt handling."""
        result=await run_in_threadpool(app.state.service.deny,GatewayDenied('ENDPOINT_NOT_ALLOWED','executor.route',error.status_code))
        return JSONResponse(result,status_code=result.pop('_http_status',error.status_code))

    async def dispatch(request: Request, webhook: bool = False) -> JSONResponse:
        service: ExecutorService=app.state.service
        raw=b''
        spans: list[tuple[int,int]]=[]
        timing_token=provider_spans.set(spans)
        try:
            for header in ('authorization','content-type','x-razorpay-signature','x-razorpay-event-id'):
                if len(request.headers.getlist(header))>1:
                    raise GatewayDenied('AMBIGUOUS_HEADERS','http.single_headers',400)
            async for chunk in request.stream():
                raw+=chunk[:262145-len(raw)]
                if len(raw)>262144:
                    raise GatewayDenied('REQUEST_TOO_LARGE','http.body_limit',413)
            if request.query_params:
                raise GatewayDenied('INVALID_REQUEST','http.no_query',400)
            if webhook:
                signature=request.headers.get('x-razorpay-signature','')
                expected=hmac.new(service.settings.webhook_secret.encode(),raw,hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature,expected):
                    raise GatewayDenied('BAD_SIGNATURE','webhook.signature',401)
            elif not hmac.compare_digest(request.headers.get('authorization',''),'Bearer '+service.settings.internal_token):
                raise GatewayDenied('UNAUTHENTICATED','executor.internal_auth',401)
            if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/json':
                raise GatewayDenied('INVALID_CONTENT_TYPE','http.json_only',415)
            data=parse_json(raw)
            if type(data) is not dict:
                raise ValueError('object required')
            def handle() -> dict[str,Any]:
                if webhook:
                    return process_webhook(service,data,raw,request.headers.get('x-razorpay-event-id',''))
                if request.url.path.endswith('/payments/get'):
                    if set(data)!={'tenant_id','payment_id'} or data['tenant_id']!=service.settings.tenant_id:
                        raise GatewayDenied('WRONG_TENANT','executor.payment_scope')
                    with Session(service.engine) as session:
                        payment=session.get(Payment,data['payment_id'])
                        if payment is None or payment.tenant_id!=data['tenant_id']:
                            raise GatewayDenied('RESOURCE_NOT_FOUND','executor.payment_scope',404)
                    return service.provider.get_payment(data['payment_id']).model_dump(mode='json')
                if set(data)!={'action','grant_token','idempotency_key','service_id'} or any(type(data[k]) is not str for k in ('grant_token','idempotency_key','service_id')):
                    raise ValueError('invalid execute envelope')
                return service.execute(parse_action(data['action']),data['grant_token'],data['idempotency_key'],data['service_id'])
            result=await run_in_threadpool(handle)
        except GatewayDenied as error:
            result=await run_in_threadpool(service.deny,error,raw)
        except (ValueError,TypeError,KeyError):
            result=await run_in_threadpool(service.deny,GatewayDenied('INVALID_REQUEST','executor.strict_schema',400),raw)
        except Exception:
            result=await run_in_threadpool(service.deny,GatewayDenied('PROVIDER_UNCERTAIN','executor.exception',503),raw)
        if request.url.path=='/internal/execute':
            result['_provider_ns']=duration_ns(spans)
        provider_spans.reset(timing_token)
        status=result.pop('_http_status',200)
        return JSONResponse(result,status_code=status,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @app.post('/internal/payments/get')
    async def get_payment(request: Request) -> JSONResponse:
        """Return an authenticated live provider projection without holding SQL locks."""
        return await dispatch(request)

    @app.post('/internal/execute')
    async def execute(request: Request) -> JSONResponse:
        """Accept only the trusted gateway's independently verifiable operation."""
        return await dispatch(request)

    @app.post('/v1/webhooks/razorpay')
    async def webhook(request: Request) -> JSONResponse:
        """Authenticate the exact raw webhook bytes before parsing or changing state."""
        return await dispatch(request,True)
    return app


def process_webhook(service: ExecutorService, data: dict[str,Any], raw: bytes, event_id: str) -> dict[str,Any]:
    """Refresh absolute live state; duplicated or reordered payloads never add money."""
    if not event_id or len(event_id)>128 or data.get('account_id')!=service.settings.account_id:
        raise GatewayDenied('WEBHOOK_SCOPE_MISMATCH','webhook.account')
    event=data.get('event')
    if event not in {'payment.authorized','payment.captured','payment.failed','refund.created','refund.processed','refund.failed'}:
        raise GatewayDenied('WEBHOOK_EVENT_NOT_ALLOWED','webhook.event')
    body_hash=hashlib.sha256(raw).hexdigest()
    with Session(service.engine) as session:
        prior=session.scalar(select(WebhookEvent).where((WebhookEvent.id==event_id)|(WebhookEvent.body_hash==body_hash)))
        prior_hash=prior.body_hash if prior else None
    if prior_hash is not None:
        if prior_hash!=body_hash:
            raise GatewayDenied('WEBHOOK_ID_CONFLICT','webhook.idempotency',409)
        return service.deny(GatewayDenied('WEBHOOK_DUPLICATE','webhook.idempotency',200),raw)
    entity=data['payload']['refund' if event.startswith('refund.') else 'payment']['entity']
    payment_id=entity['payment_id'] if event.startswith('refund.') else entity['id']
    service.refresh(payment_id)
    import time
    from sqlalchemy.exc import IntegrityError
    try:
        with Session(service.engine) as session,session.begin():
            session.add(WebhookEvent(id=event_id,body_hash=body_hash,tenant_id=service.settings.tenant_id,event_type=event,payment_id=payment_id,received_at=int(time.time())))
            receipt_id=service.audit(session,'WEBHOOK_APPLIED',True,input_hash=body_hash)
    except IntegrityError:
        return service.deny(GatewayDenied('WEBHOOK_DUPLICATE','webhook.idempotency',200),raw)
    return {'allowed':True,'reason':'WEBHOOK_APPLIED','rule_id':'executor.webhook_applied','policy_version':service.policy.policy_version,'receipt_id':receipt_id}


app=create_app()
