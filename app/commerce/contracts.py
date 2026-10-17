"""Strict commerce inputs; the client never supplies authoritative prices or tenants."""
from typing import Annotated
from pydantic import Field
from app.core.canonical import _Contract,PositiveInteger

class ProductInput(_Contract):
    """An explicit operator catalog creation, never application seed data."""
    name: str = Field(min_length=1,max_length=120)
    category: str = Field(min_length=1,max_length=80)
    description: str = Field(min_length=1,max_length=1000)
    price_paise: PositiveInteger = Field(le=10000000)

class CartLine(_Contract):
    """A product reference and bounded integer quantity."""
    product_id: str = Field(min_length=1,max_length=64)
    quantity: Annotated[int,Field(strict=True,ge=1,le=10)]

class CartInput(_Contract):
    """Prices and category snapshots are derived only from the database."""
    items: list[CartLine] = Field(min_length=1,max_length=20)
    idempotency_key: str = Field(pattern=r'^[A-Za-z0-9_-]{16,64}$')

class PaymentConfirmation(_Contract):
    """Razorpay's returned identifiers and signature; no customer amount field."""
    razorpay_order_id: str = Field(pattern=r'^order_[A-Za-z0-9]+$')
    razorpay_payment_id: str = Field(pattern=r'^pay_[A-Za-z0-9]+$')
    razorpay_signature: str = Field(pattern=r'^[a-f0-9]{64}$')

class SupportInput(_Contract):
    """Customer support intent cannot authorize a refund."""
    product_id: str = Field(min_length=1,max_length=64)
    amount_paise: PositiveInteger
    text: str = Field(min_length=1,max_length=16000)
