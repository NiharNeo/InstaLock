"""Strict provider projections and deterministic payment version hashes."""
import hashlib
from typing import Annotated, Any, Literal, Protocol
import rfc8785
from pydantic import Field, model_validator
from app.core.canonical import MAX_SAFE_INTEGER, PositiveInteger, _Contract

PaymentId = Annotated[str,Field(strict=True,pattern=r'^pay_[A-Za-z0-9]+$',max_length=128)]
RefundId = Annotated[str,Field(strict=True,pattern=r'^rfnd_[A-Za-z0-9]+$',max_length=128)]


class ProviderPayment(_Contract):
    """Only trusted payment fields used to determine the authorized effect."""
    provider_id: PaymentId
    amount_paise: PositiveInteger
    amount_refunded_paise: Annotated[int,Field(strict=True,ge=0,le=MAX_SAFE_INTEGER)]
    currency: Literal['INR']
    status: Literal['created','authorized','captured','refunded','failed']
    created_at: PositiveInteger | None = None

    @model_validator(mode='after')
    def _balance(self) -> 'ProviderPayment':
        if self.amount_refunded_paise > self.amount_paise:
            raise ValueError('invalid provider balance')
        return self

    @property
    def version_hash(self) -> str:
        """SHA-256 of JCS [provider_id, amount, amount_refunded, status]."""
        return hashlib.sha256(rfc8785.dumps([self.provider_id,self.amount_paise,self.amount_refunded_paise,self.status])).hexdigest()


class ProviderRefund(_Contract):
    """Normalized actual refund response, never synthesized by application code."""
    provider_id: RefundId
    payment_id: PaymentId
    amount_paise: PositiveInteger
    currency: Literal['INR']
    status: Literal['pending','processed','failed']
    receipt: str | None


class ProviderUncertain(Exception):
    """The provider outcome is unknown; retry only with the original provider key."""


class ProviderRejected(Exception):
    """The provider definitively rejected an attempted request."""


class RefundProvider(Protocol):
    """Provider boundary; only the executor holds an implementation with secrets."""
    def get_payment(self, payment_id: str) -> ProviderPayment:
        """Fetch authoritative current payment state."""
        ...

    def create_refund(self, payment_id: str, amount_paise: int, idempotency_ref: str) -> ProviderRefund:
        """Send the exact refund with durable provider-side idempotency."""
        ...

    def find_refund(self, payment_id: str, idempotency_ref: str) -> ProviderRefund | None:
        """Query actual provider refunds for this operation's immutable receipt."""
        ...
