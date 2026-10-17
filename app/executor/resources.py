"""Absolute provider-state projection with SQL fencing and no webhook increments."""
import time
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.core.canonical import MAX_SAFE_INTEGER
from app.core.errors import GatewayDenied
from app.core.policy import PaymentSnapshot
from app.executor.models import ProviderPayment
from intentlock.db import Order, Payment, Resource


def apply_payment(session: Session, live: ProviderPayment, tenant_id: str) -> PaymentSnapshot:
    """Project a real provider response into its pre-provisioned tenant mapping.

    Caller serializes provider fetch/application for a payment using a lease or
    observes the old cache version before fetching and checks it before applying.
    No customer order or payment mapping is created from a provider webhook.
    """
    payment = session.scalar(select(Payment).where(Payment.id==live.provider_id,Payment.tenant_id==tenant_id).with_for_update())
    if payment is None:
        raise GatewayDenied('RESOURCE_NOT_FOUND','executor.payment_scope',404)
    order = session.get(Order,payment.order_id)
    if order is None or order.tenant_id != tenant_id or order.paid_paise != live.amount_paise or order.currency != live.currency:
        raise GatewayDenied('RESOURCE_MISMATCH','executor.provider_binding')
    cached = session.get(Resource,payment.id)
    changed = (cached is not None and cached.version_hash != live.version_hash) or order.refunded_paise != live.amount_refunded_paise
    if changed:
        if order.version >= MAX_SAFE_INTEGER:
            raise GatewayDenied('STALE_RESOURCE','executor.version_limit')
        order.refunded_paise = live.amount_refunded_paise
        order.version += 1
    values = dict(tenant_id=tenant_id,provider_id=live.provider_id,amount_paise=live.amount_paise,amount_refunded_paise=live.amount_refunded_paise,currency=live.currency,status=live.status,version_hash=live.version_hash,synced_at=int(time.time()))
    if cached is None:
        session.add(Resource(id=payment.id,**values))
    else:
        for name,value in values.items():
            setattr(cached,name,value)
    session.flush()
    return PaymentSnapshot(payment_id=payment.id,order_id=order.id,tenant_id=tenant_id,currency=live.currency,original_destination=order.destination,destination_kind=payment.destination_kind,paid_paise=live.amount_paise,refunded_paise=live.amount_refunded_paise,order_version=order.version,in_flight_refunds=1 if payment.in_flight else 0,version_hash=live.version_hash,provider_status=live.status)
