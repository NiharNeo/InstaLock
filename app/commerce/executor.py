"""Trusted order creation and payment verification, executed beside provider secrets."""
import hashlib
import hmac
import re
import time
from typing import Any
from sqlalchemy import select,update
from sqlalchemy.orm import Session
from app.core.errors import GatewayDenied
from app.executor.resources import apply_payment
from app.commerce.contracts import PaymentConfirmation
from intentlock.db import StoreCheckout,Order,Payment


def checkout_rpc(service: Any,data: dict[str,Any],operation: str) -> dict[str,Any]:
    """Bind provider orders to persisted priced baskets; never trust browser success alone."""
    expected={'checkout_id','tenant_id'}|({'confirmation'} if operation=='confirm' else set())
    if set(data)!=expected or data['tenant_id']!=service.settings.tenant_id or not isinstance(data['checkout_id'],str):
        raise GatewayDenied('WRONG_TENANT','commerce.executor_scope')
    with Session(service.engine) as s:
        row=s.get(StoreCheckout,data['checkout_id'])
        if row is None or row.tenant_id!=service.settings.tenant_id:raise GatewayDenied('CHECKOUT_NOT_FOUND','commerce.scope',404)
        identifier=row.id;amount=row.amount_paise;provider_order=row.provider_order_id;status=row.status
    if operation=='create' and status=='REQUESTED':
        with Session(service.engine) as s,s.begin():
            changed=s.execute(update(StoreCheckout).where(StoreCheckout.id==identifier,StoreCheckout.status=='REQUESTED').values(status='CREATING'))
            if changed.rowcount!=1:raise GatewayDenied('CHECKOUT_PENDING','commerce.reservation',409)
        try:
            result=service.provider.create_order(amount,identifier)
            provider_order=result['id']
            if not re.fullmatch(r'order_[A-Za-z0-9]+',provider_order) or result.get('amount')!=amount or result.get('currency')!='INR' or result.get('receipt')!=identifier:
                raise ValueError('provider order mismatch')
            with Session(service.engine) as s,s.begin():
                s.execute(update(StoreCheckout).where(StoreCheckout.id==identifier,StoreCheckout.status=='CREATING').values(provider_order_id=provider_order,status='AWAITING_PAYMENT'))
        except Exception:
            # Never repeat an ambiguous provider POST. A new checkout requires a new customer action.
            raise GatewayDenied('CHECKOUT_UNCERTAIN','commerce.provider_create',503) from None
    elif not provider_order:
        raise GatewayDenied('CHECKOUT_PENDING','commerce.reservation',409)
    if operation=='confirm':
        body=PaymentConfirmation.model_validate(data['confirmation'])
        expected_signature=hmac.new(service.settings.key_secret.encode(),(str(provider_order)+'|'+body.razorpay_payment_id).encode(),hashlib.sha256).hexdigest()
        if body.razorpay_order_id!=provider_order or not hmac.compare_digest(expected_signature,body.razorpay_signature):
            raise GatewayDenied('BAD_SIGNATURE','commerce.checkout_signature',401)
        payment=service.provider.checkout_payment(body.razorpay_payment_id)
        bind_payment(service,identifier,payment)
    elif operation=='status' and status!='PAID':
        payments=service.provider.order_payments(str(provider_order))
        captured=[p for p in payments if p.get('status')=='captured']
        if len(captured)>1:raise GatewayDenied('PAYMENT_AMBIGUOUS','commerce.captured_payment',503)
        if captured:bind_payment(service,identifier,captured[0])
    with Session(service.engine) as s:
        row=s.get(StoreCheckout,identifier)
        assert row is not None
        order=s.get(Order,row.provider_order_id) if row.status=='PAID' else None
        return {'checkout_id':row.id,'provider_order_id':row.provider_order_id,'payment_id':row.payment_id,'status':row.status,'amount_paise':row.amount_paise,'currency':'INR','items':row.items,'key_id':service.settings.key_id,'refunded_paise':order.refunded_paise if order else 0,'paid_at':row.paid_at}


def bind_payment(service: Any,checkout_id: str,value: dict[str,Any]) -> None:
    """Map only a captured, provider-fetched payment with exact order/amount/currency."""
    live=service.provider._payment(value)
    if live.status!='captured':raise GatewayDenied('PAYMENT_NOT_CAPTURED','commerce.capture',409)
    with Session(service.engine) as s,s.begin():
        s.execute(update(StoreCheckout).where(StoreCheckout.id==checkout_id).values(status=StoreCheckout.status))
        row=s.get(StoreCheckout,checkout_id)
        if row is None or row.tenant_id!=service.settings.tenant_id:raise GatewayDenied('CHECKOUT_NOT_FOUND','commerce.scope',404)
        if value.get('order_id')!=row.provider_order_id or live.amount_paise!=row.amount_paise or live.currency!='INR':
            raise GatewayDenied('RESOURCE_MISMATCH','commerce.provider_binding')
        if row.status=='PAID':
            if row.payment_id!=live.provider_id:raise GatewayDenied('PAYMENT_AMBIGUOUS','commerce.payment_binding')
            return
        if row.status!='AWAITING_PAYMENT':raise GatewayDenied('CHECKOUT_PENDING','commerce.state',409)
        if s.get(Order,row.provider_order_id) or s.get(Payment,live.provider_id):raise GatewayDenied('RESOURCE_MISMATCH','commerce.existing_mapping')
        s.add(Order(id=row.provider_order_id,tenant_id=row.tenant_id,paid_paise=live.amount_paise,refunded_paise=0,currency='INR',destination='original_payment',version=1));s.flush()
        s.add(Payment(id=live.provider_id,tenant_id=row.tenant_id,order_id=row.provider_order_id,destination_kind='original_payment',in_flight=False));s.flush()
        apply_payment(s,live,row.tenant_id)
        row.payment_id=live.provider_id;row.status='PAID';row.paid_at=int(time.time())
        # Receipt contains no shopper capability, signatures or customer text.
        from app.core.receipts import append_receipt
        from uuid import uuid4
        append_receipt(s,tenant_id=row.tenant_id,id=str(uuid4()),timestamp=int(time.time()),allowed=True,reason='STORE_PAYMENT_VERIFIED',rule_id='commerce.provider_binding',policy_version=service.policy.policy_version,input_hash=hashlib.sha256(row.id.encode()).hexdigest(),action_digest=None,request_id=row.id,refund_id=None)
