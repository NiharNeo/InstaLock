"""Public shopper capabilities and authenticated catalog administration."""
import hashlib
import hmac
import re
import os
from urllib.parse import urlsplit
import secrets
import time
from typing import Any
from uuid import uuid4
import rfc8785
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.auth.service import authenticate_operator,secret_hash,check_origin
from app.commerce.contracts import ProductInput,CartInput,PaymentConfirmation,SupportInput
from app.core.canonical import _load_json
from app.core.errors import GatewayDenied
from app.core.receipts import reserve_audit_transaction
from app.intake.service import create_ticket,TicketInput,rate_limit
from intentlock.db import StoreProduct,StoreCheckout,StoreSupportRequest,SupportChannel,Order

router=APIRouter()
COOKIE='intentlock_shopper'


def product_payload(row: StoreProduct) -> dict[str,Any]:
    """Expose catalog content only, without internal tenant identifiers."""
    return {key:getattr(row,key) for key in ('id','name','category','description','price_paise')}


def channel_scope(s: Session,channel: str) -> SupportChannel:
    """Resolve storefront scope only from an active provisioned channel."""
    row=s.get(SupportChannel,channel)
    if row is None or not row.active:raise GatewayDenied('STORE_UNAVAILABLE','commerce.channel',404)
    return row


def shopper(request: Request) -> str:
    """Require a private browser capability for purchase history and support."""
    value=request.cookies.get(COOKIE,'')
    if not re.fullmatch(r'[A-Za-z0-9_-]{64}',value):raise GatewayDenied('SHOPPER_SESSION_REQUIRED','commerce.shopper',401)
    return secret_hash(value)


def owned(s: Session,request: Request,channel: str,identifier: str) -> StoreCheckout:
    """Hide existence of checkouts owned by another shopper or tenant."""
    scope=channel_scope(s,channel);row=s.get(StoreCheckout,identifier)
    if row is None or row.tenant_id!=scope.tenant_id or row.channel_id!=channel or not hmac.compare_digest(row.shopper_hash,shopper(request)):
        raise GatewayDenied('CHECKOUT_NOT_FOUND','commerce.ownership',404)
    return row


async def read_body(request: Request) -> Any:
    """Bound and strictly parse original wire JSON, including duplicate-key rejection."""
    if request.query_params or any(len(request.headers.getlist(h))>1 for h in ('cookie','origin','content-type','content-length','x-csrf-token','authorization')):
        raise GatewayDenied('INVALID_REQUEST','commerce.headers',400)
    if request.headers.get('content-type','').split(';')[0]!='application/json':raise GatewayDenied('INVALID_CONTENT_TYPE','commerce.json',415)
    raw=b''
    async for part in request.stream():
        raw+=part[:32769-len(raw)]
        if len(raw)>32768:raise GatewayDenied('REQUEST_TOO_LARGE','commerce.body',413)
    try:return _load_json(raw)
    except (ValueError,TypeError,UnicodeError):raise GatewayDenied('INVALID_REQUEST','commerce.schema',400) from None


async def failure(request: Request,error: Exception) -> JSONResponse:
    """Write a stable denial receipt without storing checkout secrets or raw prose."""
    if isinstance(error,GatewayDenied):denied=error
    elif isinstance(error,(ValueError,TypeError)):denied=GatewayDenied('INVALID_REQUEST','commerce.schema',400)
    else:denied=GatewayDenied('COMMERCE_UNAVAILABLE','commerce.exception',503)
    body,status=await run_in_threadpool(request.app.state.gateway.deny,b'',denied,getattr(request.state,'receipt_tenant',None),getattr(request.state,'receipt_actor',None))
    return JSONResponse(body,status_code=status)


def catalog(request: Request,channel: str) -> dict[str,Any]:
    """Return actual active products and the current published payment-level policy."""
    gateway=request.app.state.gateway
    with Session(gateway.engine) as s,s.begin():
        reserve_audit_transaction(s)
        scope=channel_scope(s,channel)
        rows=list(s.scalars(select(StoreProduct).where(StoreProduct.tenant_id==scope.tenant_id,StoreProduct.active.is_(True)).order_by(StoreProduct.category,StoreProduct.name).limit(200)))
        from app.api.insights import policy_payload
        policy=policy_payload(s,gateway,scope.tenant_id)
        s.info.update(receipt_tenant=scope.tenant_id)
        gateway.audit(s,b'','STORE_CATALOG_READ','commerce.catalog_public',True)
        return {'operator_url':gateway.settings.origin if gateway.settings.origin.startswith('https://') or request.headers.get('host')==urlsplit(gateway.settings.origin).netloc else None,'channel':channel,'products':[product_payload(row) for row in rows],'mode':'test','refund_policy':policy['rules']}


@router.get('/public/store/{channel}/catalog')
async def get_catalog(request: Request,channel: str) -> JSONResponse:
    """Load a real catalog and establish an anonymous same-origin shopper session."""
    try:
        result=await run_in_threadpool(catalog,request,channel)
        response=JSONResponse(result)
        if not re.fullmatch(r'[A-Za-z0-9_-]{64}',request.cookies.get(COOKIE,'')):
            response.set_cookie(COOKIE,secrets.token_urlsafe(48),httponly=True,secure=request.app.state.gateway.settings.origin.startswith('https://') or request.headers.get('host')==urlsplit(os.environ.get('STORE_PUBLIC_ORIGIN','')).netloc,samesite='strict',path='/public/store',max_age=604800)
        return response
    except Exception as error:return await failure(request,error)


def admin(request: Request,body: ProductInput | None) -> dict[str,Any]:
    """Allow only a real tenant operator to insert catalog products, with CSRF on writes."""
    g=request.app.state.gateway
    with Session(g.engine) as s,s.begin():
        reserve_audit_transaction(s);human=authenticate_operator(s,request,csrf=body is not None,origin=g.settings.origin)
        if body:
            row=StoreProduct(id=uuid4().hex,tenant_id=human.tenant_id,**body.model_dump(),active=True,created_at=int(time.time()));s.add(row);s.flush()
            g.audit(s,b'','CATALOG_PRODUCT_CREATED','commerce.catalog_admin',True)
            return product_payload(row)
        rows=list(s.scalars(select(StoreProduct).where(StoreProduct.tenant_id==human.tenant_id).order_by(StoreProduct.created_at).limit(200)))
        channels=list(s.scalars(select(SupportChannel.id).where(SupportChannel.tenant_id==human.tenant_id,SupportChannel.active.is_(True))))
        categories: dict[str,dict[str,Any]]={}
        purchases=list(s.scalars(select(StoreCheckout).where(StoreCheckout.tenant_id==human.tenant_id,StoreCheckout.status=='PAID').limit(10001)))
        if len(purchases)>10000:raise GatewayDenied('ANALYTICS_RANGE_TOO_LARGE','commerce.analytics',413)
        for purchase in purchases:
            for line in purchase.items:
                entry=categories.setdefault(line['category'],{'category':line['category'],'units':0,'sales_paise':0})
                entry['units']+=line['quantity'];entry['sales_paise']+=line['price_paise']*line['quantity']
        g.audit(s,b'','CATALOG_READ','commerce.catalog_admin',True)
        return {'products':[product_payload(r) for r in rows],'channels':channels,'categories':list(categories.values()),'paid_store_orders':len(purchases)}


@router.get('/v1/store/catalog')
async def get_admin(request: Request) -> JSONResponse:
    """Read tenant catalog and actual purchased category metrics."""
    try:return JSONResponse(await run_in_threadpool(admin,request,None))
    except Exception as error:return await failure(request,error)


@router.post('/v1/store/catalog')
async def post_product(request: Request) -> JSONResponse:
    """Persist an explicitly authored catalog product, never startup seed data."""
    try:return JSONResponse(await run_in_threadpool(admin,request,ProductInput.model_validate(await read_body(request))),status_code=201)
    except Exception as error:return await failure(request,error)


def public_operation(request: Request,channel: str,operation: str,identifier: str | None,body: Any) -> dict[str,Any]:
    """Perform shopper-scoped checkout/support work with no privilege over refunds."""
    g=request.app.state.gateway
    public_origin=os.environ.get('STORE_PUBLIC_ORIGIN','')
    if public_origin:
        parsed=urlsplit(public_origin)
        if parsed.scheme!='https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise GatewayDenied('STORE_ORIGIN_INVALID','commerce.origin',503)
    check_origin(request,public_origin if request.headers.get('origin')==public_origin and public_origin else g.settings.origin)
    if not g.executor:raise GatewayDenied('EXECUTOR_UNAVAILABLE','commerce.executor',503)
    with Session(g.engine) as s,s.begin():
        reserve_audit_transaction(s)
        scope=channel_scope(s,channel);request.state.receipt_tenant=scope.tenant_id
        if operation!='history':
            if request.client is None:raise GatewayDenied('INTAKE_CLIENT_UNAVAILABLE','commerce.client',503)
            rate_limit(s,request.client.host)
        owner=shopper(request)
        if operation=='history':
            rows=list(s.scalars(select(StoreCheckout).where(StoreCheckout.tenant_id==scope.tenant_id,StoreCheckout.channel_id==channel,StoreCheckout.shopper_hash==owner).order_by(StoreCheckout.created_at.desc()).limit(30)))
            s.info.update(receipt_tenant=scope.tenant_id);g.audit(s,b'','STORE_ORDERS_READ','commerce.ownership',True)
            return {'orders':[{'checkout_id':r.id,'provider_order_id':r.provider_order_id,'status':r.status,'amount_paise':r.amount_paise,'items':r.items,'created_at':r.created_at,'refunded_paise':(s.get(Order,r.provider_order_id).refunded_paise if r.status=='PAID' else 0)} for r in rows]}
        if operation=='create':
            cart=CartInput.model_validate(body)
            if len({line.product_id for line in cart.items})!=len(cart.items):raise GatewayDenied('DUPLICATE_CART_ITEM','commerce.cart',400)
            fingerprint=hashlib.sha256(rfc8785.dumps(sorted([line.model_dump() for line in cart.items],key=lambda x:x['product_id']))).hexdigest()
            row=s.scalar(select(StoreCheckout).where(StoreCheckout.tenant_id==scope.tenant_id,StoreCheckout.shopper_hash==owner,StoreCheckout.idempotency_key==cart.idempotency_key))
            if row:
                if row.basket_hash!=fingerprint or row.channel_id!=channel:raise GatewayDenied('IDEMPOTENCY_CONFLICT','commerce.cart_key',409)
            else:
                lines=[]
                for line in cart.items:
                    product=s.get(StoreProduct,line.product_id)
                    if product is None or product.tenant_id!=scope.tenant_id or not product.active:raise GatewayDenied('PRODUCT_UNAVAILABLE','commerce.catalog',404)
                    lines.append({**product_payload(product),'product_id':product.id,'quantity':line.quantity})
                total=sum(line['price_paise']*line['quantity'] for line in lines)
                if not 100<=total<=10000000:raise GatewayDenied('INVALID_CART_TOTAL','commerce.amount',400)
                row=StoreCheckout(id=uuid4().hex,tenant_id=scope.tenant_id,channel_id=channel,shopper_hash=owner,idempotency_key=cart.idempotency_key,basket_hash=fingerprint,items=lines,amount_paise=total,status='REQUESTED',created_at=int(time.time()))
                s.add(row);s.flush();g.audit(s,b'','STORE_CHECKOUT_CREATED','commerce.server_price',True,request_id=row.id)
        else:row=owned(s,request,channel,str(identifier))
        rpc={'checkout_id':row.id,'tenant_id':row.tenant_id}
        if operation=='support':
            support=SupportInput.model_validate(body)
            if row.status!='PAID':raise GatewayDenied('PAYMENT_NOT_CAPTURED','commerce.support',409)
            line=next((line for line in row.items if line['product_id']==support.product_id),None)
            order=s.get(Order,row.provider_order_id)
            if line is None or order is None or support.amount_paise>min(line['quantity']*line['price_paise'],order.paid_paise-order.refunded_paise):raise GatewayDenied('INVALID_REFUND_AMOUNT','commerce.purchased_item',400)
            result=create_ticket(s,TicketInput(channel_id=channel,order_id=row.provider_order_id,text=support.text),g.policy.policy_version)
            s.add(StoreSupportRequest(ticket_id=result['ticket_id'],checkout_id=row.id,product_id=support.product_id,requested_paise=support.amount_paise))
            return result
        if operation=='confirm':rpc['confirmation']=PaymentConfirmation.model_validate(body).model_dump()
    # Provider I/O occurs only after releasing the gateway's database transaction.
    result=g.executor.call('internal/store/'+operation,rpc)
    with Session(g.engine) as s,s.begin():
        reserve_audit_transaction(s);s.info.update(receipt_tenant=rpc['tenant_id'])
        g.audit(s,b'','STORE_CHECKOUT_'+operation.upper(),'commerce.'+operation,True,request_id=str(rpc['checkout_id']))
    return result


@router.get('/public/store/{channel}/orders')
async def history(request: Request,channel: str) -> JSONResponse:
    """List only this browser's purchases; no email/order-ID enumeration."""
    try:return JSONResponse(await run_in_threadpool(public_operation,request,channel,'history',None,None))
    except Exception as error:return await failure(request,error)


@router.post('/public/store/{channel}/checkouts')
async def checkout(request: Request,channel: str) -> JSONResponse:
    """Reserve a priced basket and create exactly one provider order for its key."""
    try:return JSONResponse(await run_in_threadpool(public_operation,request,channel,'create',None,await read_body(request)))
    except Exception as error:return await failure(request,error)


@router.post('/public/store/{channel}/checkouts/{identifier}/{operation}')
async def checkout_action(request: Request,channel: str,identifier: str,operation: str) -> JSONResponse:
    """Confirm/check a payment or submit support; refund execution is never public."""
    try:
        if operation not in {'confirm','status','support'}:raise GatewayDenied('ENDPOINT_NOT_ALLOWED','commerce.route',404)
        body=await read_body(request)
        if operation=='status' and body!={}:raise GatewayDenied('INVALID_REQUEST','commerce.empty_status',400)
        return JSONResponse(await run_in_threadpool(public_operation,request,channel,operation,identifier,body))
    except Exception as error:return await failure(request,error)
