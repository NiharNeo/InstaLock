"""Trusted adapter reading live payments and orders from the actual database."""
from typing import Protocol
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.errors import GatewayDenied
from app.core.policy import PaymentSnapshot
from intentlock.db import Order, Payment


class ResourceAdapter(Protocol):
    """Contract for fetching authoritative current resource state."""
    def fetch(self, session: Session, payment_id: str, tenant_id: str, *, for_update: bool = False) -> PaymentSnapshot:
        """Read live state; fail on missing, inconsistent, or out-of-scope resources."""
        ...


class DatabasePaymentAdapter:
    """One real payment per order, with financial state owned by the order row."""
    def fetch(self, session: Session, payment_id: str, tenant_id: str, *, for_update: bool = False) -> PaymentSnapshot:
        """Re-fetch trusted current state; never use ticket text or client balances."""
        statement = select(Payment,Order).join(Order,Payment.order_id == Order.id).where(Payment.id == payment_id, Payment.tenant_id == tenant_id, Order.tenant_id == tenant_id)
        if for_update:
            statement = statement.with_for_update()
        found = session.execute(statement).one_or_none()
        if found is None:
            raise GatewayDenied('RESOURCE_NOT_FOUND','resource.tenant_lookup',404)
        payment, order = found
        if type(payment.in_flight) is not bool:
            raise GatewayDenied('INVALID_RESOURCE','resource.integrity')
        try:
            resource = PaymentSnapshot(payment_id=payment.id,order_id=order.id,tenant_id=payment.tenant_id,currency=order.currency,original_destination=order.destination,destination_kind=payment.destination_kind,paid_paise=order.paid_paise,refunded_paise=order.refunded_paise,order_version=order.version,in_flight_refunds=1 if payment.in_flight else 0)
        except (ValidationError, ValueError):
            raise GatewayDenied('INVALID_RESOURCE','resource.integrity') from None
        if resource.refunded_paise > resource.paid_paise:
            raise GatewayDenied('INVALID_RESOURCE','resource.integrity')
        return resource
