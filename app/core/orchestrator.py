"""Atomic real local-ledger refunds, sharing the grant's SQL transaction."""
from uuid import uuid4
from sqlalchemy import update
from sqlalchemy.orm import Session
from app.core.canonical import MAX_SAFE_INTEGER, ProposedAction
from app.core.errors import GatewayDenied
from app.core.policy import PaymentSnapshot
from intentlock.db import Order, Payment, Proposal, Refund


class RefundOrchestrator:
    """Reserve a live payment, commit its ledger effect, and release the reservation."""
    def execute(self, session: Session, action: ProposedAction, resource: PaymentSnapshot, grant_id: str, proposal_id: str) -> str:
        """Execute only inside the caller's grant/policy/audit transaction.

        No external payment API is called. An external adapter requires its own
        durable outbox and provider idempotency; never put a network effect here.
        """
        reserved = session.execute(update(Payment).where(Payment.id == resource.payment_id,Payment.tenant_id == action.tenant_id,Payment.order_id == resource.order_id,Payment.destination_kind == 'original_payment',Payment.in_flight.is_(False)).values(in_flight=True))
        if reserved.rowcount != 1:
            raise GatewayDenied('REFUND_IN_FLIGHT','orchestrator.payment_reservation')
        changed = session.execute(update(Order).where(Order.id == action.resource_ref,Order.tenant_id == action.tenant_id,Order.version == action.resource_version,Order.version < MAX_SAFE_INTEGER,Order.currency == 'INR',Order.destination == resource.original_destination,Order.paid_paise == resource.paid_paise,Order.refunded_paise == resource.refunded_paise,Order.refunded_paise + action.args.amount_paise <= Order.paid_paise).values(refunded_paise=Order.refunded_paise+action.args.amount_paise,version=Order.version+1))
        if changed.rowcount != 1:
            raise GatewayDenied('STALE_RESOURCE','orchestrator.resource_compare_and_swap')
        advanced = session.execute(update(Proposal).where(Proposal.id == proposal_id,Proposal.tenant_id == action.tenant_id,Proposal.status == 'APPROVED',Proposal.grant_id == grant_id).values(status='EXECUTED'))
        if advanced.rowcount != 1:
            raise GatewayDenied('PROPOSAL_NOT_APPROVED','orchestrator.approved_proposal')
        refund_id = str(uuid4())
        session.add(Refund(id=refund_id,grant_id=grant_id,order_id=resource.order_id,amount_paise=action.args.amount_paise,destination=resource.original_destination))
        session.execute(update(Payment).where(Payment.id == resource.payment_id,Payment.tenant_id == action.tenant_id).values(in_flight=False))
        session.flush()
        return refund_id
