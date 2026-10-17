"""Trusted policy enforcement and atomic refund execution."""
import base64
import hashlib
import hmac
import time
from uuid import uuid4
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine
from intentlock.config import Settings
from intentlock.db import Execution, Order, Receipt, Refund, Ticket, UsedGrant, User
from intentlock.schema import Action, Envelope, canonical, digest

class Denied(Exception):
    """A stable policy decision, never a business effect."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)

def require(condition: bool, reason: str) -> None:
    """Deny unless the condition is positively established."""
    if not condition:
        raise Denied(reason)

def authenticate(header: str | None, token: str) -> None:
    """Compare scoped bearer credentials in constant time."""
    require(header is not None and hmac.compare_digest(header.encode(), ('Bearer ' + token).encode()), 'UNAUTHENTICATED')

def check_action(session: Session, action: Action, settings: Settings) -> Order:
    """Validate trusted tenant, association, version, balance, and destination."""
    require(action.tenant_id == settings.agent_tenant, 'TENANT_MISMATCH')
    order = session.get(Order, action.order_id)
    ticket = session.get(Ticket, action.ticket_id)
    require(order is not None and ticket is not None, 'RESOURCE_NOT_FOUND')
    assert order is not None and ticket is not None
    require(order.tenant_id == action.tenant_id == ticket.tenant_id, 'TENANT_MISMATCH')
    require(ticket.order_id == order.id, 'TICKET_MISMATCH')
    require(order.version == action.resource_version, 'STALE_RESOURCE')
    require(action.destination == order.destination, 'DESTINATION_MISMATCH')
    require(action.currency == order.currency == 'INR', 'CURRENCY_MISMATCH')
    require(action.amount_paise <= settings.max_refund_paise, 'POLICY_LIMIT')
    require(action.amount_paise <= order.paid_paise - order.refunded_paise, 'INSUFFICIENT_BALANCE')
    return order

def receipt(session: Session, settings: Settings, raw: bytes, reason: str, envelope: Envelope | None = None, refund_id: str | None = None, allowed: bool = False, proposed: Action | None = None) -> dict[str, Any]:
    """Persist a decision and return its stable, minimal public representation."""
    result = dict(id=str(uuid4()), timestamp=int(time.time()), allowed=allowed, reason=reason, rule_id='refund.' + reason.lower(), policy_version=settings.policy_version, input_hash=hashlib.sha256(raw).hexdigest(), action_digest=digest(envelope.action) if envelope else digest(proposed) if proposed else None, request_id=envelope.request_id if envelope else None, refund_id=refund_id)
    from app.core.receipts import append_receipt
    action=envelope.action if envelope else proposed
    append_receipt(session,tenant_id=settings.agent_tenant,actor_id=None,grant_jti=envelope.grant.grant_id if envelope else None,**result)
    return result

def record_deny(engine: Engine, settings: Settings, raw: bytes, reason: str, envelope: Envelope | None = None) -> dict[str, Any]:
    """Persist a denial in a fresh transaction after any effect rollback."""
    with Session(engine) as session, session.begin():
        return receipt(session, settings, raw, reason, envelope)

def execute(engine: Engine, settings: Settings, raw: bytes, envelope: Envelope) -> dict[str, Any]:
    """Commit grant use, ledger effect, idempotency result, and receipt together."""
    action, grant = envelope.action, envelope.grant
    try:
        with Session(engine) as session, session.begin():
            require(action.tenant_id == settings.agent_tenant == grant.tenant_id, 'TENANT_MISMATCH')
            user = session.get(User, grant.signer_id)
            require(user is not None and user.active, 'SIGNER_UNTRUSTED')
            assert user is not None
            require(user.tenant_id == grant.tenant_id, 'TENANT_MISMATCH')
            try:
                key = Ed25519PublicKey.from_public_bytes(base64.b64decode(user.public_key, validate=True))
                key.verify(base64.b64decode(envelope.signature, validate=True), canonical(grant))
            except (ValueError, InvalidSignature):
                raise Denied('INVALID_SIGNATURE') from None
            require(grant.action_digest == digest(action), 'ACTION_MISMATCH')
            fingerprint = digest(envelope)
            execution_id = action.tenant_id + '/' + envelope.request_id
            prior = session.get(Execution, execution_id)
            if prior:
                require(prior.fingerprint == fingerprint, 'IDEMPOTENCY_CONFLICT')
                result = receipt(session, settings, raw, 'IDEMPOTENT_RETRY', envelope, prior.result['refund_id'], True)
                return result
            require(grant.policy_version == settings.policy_version, 'POLICY_CHANGED')
            now = int(time.time())
            require(grant.issued_at <= now < grant.expires_at and 0 < grant.expires_at - grant.issued_at <= settings.max_grant_seconds, 'GRANT_TIME_INVALID')
            require(session.get(UsedGrant, grant.grant_id) is None, 'GRANT_USED')
            order = check_action(session, action, settings)
            session.add(UsedGrant(id=grant.grant_id, payload=grant.model_dump(), signature=envelope.signature))
            session.flush()
            updated = session.execute(update(Order).where(Order.id == order.id, Order.version == action.resource_version, Order.refunded_paise + action.amount_paise <= Order.paid_paise).values(refunded_paise=Order.refunded_paise + action.amount_paise, version=Order.version + 1))
            require(updated.rowcount == 1, 'STALE_RESOURCE')
            refund_id = str(uuid4())
            session.add(Refund(id=refund_id, grant_id=grant.grant_id, order_id=order.id, amount_paise=action.amount_paise, destination=action.destination))
            result = receipt(session, settings, raw, 'AUTHORIZED', envelope, refund_id, True)
            session.add(Execution(id=execution_id, fingerprint=fingerprint, result=result))
            return result
    except IntegrityError:
        # Another worker may have committed the same grant while we were validating.
        with Session(engine) as session:
            prior = session.get(Execution, envelope.action.tenant_id + '/' + envelope.request_id)
            if prior and prior.fingerprint == digest(envelope):
                with Session(engine) as audit, audit.begin():
                    return receipt(audit, settings, raw, 'IDEMPOTENT_RETRY', envelope, prior.result['refund_id'], True)
        raise Denied('GRANT_USED') from None
