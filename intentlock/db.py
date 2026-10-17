"""Portable relational storage; application startup never seeds records."""
from typing import Any
from sqlalchemy import JSON, BigInteger, Boolean, CheckConstraint, ForeignKey, Index, String, UniqueConstraint, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    """Declarative schema base."""

class User(Base):
    """Provisioned human signing identity; the private key stays offline."""
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    public_key: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean)

class Order(Base):
    """Trusted order state and remaining refundable balance."""
    __tablename__ = 'orders'
    __table_args__ = (CheckConstraint('paid_paise > 0 AND refunded_paise >= 0 AND refunded_paise <= paid_paise'), CheckConstraint('version > 0'))
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    paid_paise: Mapped[int] = mapped_column(BigInteger)
    refunded_paise: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    destination: Mapped[str] = mapped_column(String(128))
    version: Mapped[int] = mapped_column(BigInteger)

class Ticket(Base):
    """Untrusted customer text with trusted order association."""
    __tablename__ = 'tickets'
    __table_args__=(Index('ix_tickets_tenant_id','tenant_id','id'),)
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    order_id: Mapped[str | None] = mapped_column(ForeignKey('orders.id'),nullable=True)
    text: Mapped[str] = mapped_column(String)
    redacted_text: Mapped[str | None] = mapped_column(String,nullable=True)
    source_id: Mapped[str | None] = mapped_column(String(64),nullable=True,unique=True)
    processing_status: Mapped[str] = mapped_column(String(16),default='QUEUED',server_default='QUEUED')
    claimed_by: Mapped[str | None] = mapped_column(String(128),nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(128),nullable=True)
    lease_until: Mapped[int | None] = mapped_column(BigInteger,nullable=True)

class UsedGrant(Base):
    """Grant lifecycle: legacy rows are USED; JWT consent starts ACTIVE."""
    __tablename__ = 'grants'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default='USED', server_default='USED')
    kid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

class KeyRegistry(Base):
    """Immutable public key ownership; rotation adds a kid, revocation disables it."""
    __tablename__ = 'key_registry'
    kid: Mapped[str] = mapped_column(String(128), primary_key=True)
    public_key: Mapped[str] = mapped_column(String(128))
    operator_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    tenant_id: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[int] = mapped_column(BigInteger)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

class Refund(Base):
    """Authoritative local ledger entry, created only by the gateway."""
    __tablename__ = 'refunds'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey('grants.id'), unique=True)
    order_id: Mapped[str] = mapped_column(ForeignKey('orders.id'))
    amount_paise: Mapped[int] = mapped_column(BigInteger)
    destination: Mapped[str] = mapped_column(String(128))

class Execution(Base):
    """Successful idempotency result, scoped to the configured agent tenant."""
    __tablename__ = 'executions'
    id: Mapped[str] = mapped_column(String(257), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict[str, Any]] = mapped_column(JSON)

class Receipt(Base):
    """Minimal decision evidence; ticket text and credentials are excluded."""
    __tablename__ = 'receipts'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    decision: Mapped[str | None] = mapped_column(String(5), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    grant_jti: Mapped[str | None] = mapped_column(String(128), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    operation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    receipt_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    __table_args__ = (UniqueConstraint('tenant_id','seq',name='uq_receipts_tenant_seq'),)
    timestamp: Mapped[int] = mapped_column(BigInteger)
    allowed: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(128))
    policy_version: Mapped[str] = mapped_column(String(128))
    input_hash: Mapped[str] = mapped_column(String(64))
    action_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    refund_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

def engine_for(url: str) -> Engine:
    """Create a database engine with SQLite foreign-key enforcement."""
    engine = create_engine(url, connect_args={'check_same_thread': False, 'timeout': 20, 'autocommit': False} if url.startswith('sqlite') else {}, pool_pre_ping=True)
    if url.startswith('sqlite'):
        @event.listens_for(engine, 'connect')
        def configure(connection: Any, _: Any) -> None:
            connection.autocommit = True
            connection.execute('PRAGMA foreign_keys=ON')
            connection.autocommit = False
    return engine

class Payment(Base):
    """Actual payment-to-order mapping and persisted refund reservation state."""
    __tablename__ = 'payments'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    order_id: Mapped[str] = mapped_column(ForeignKey('orders.id'), unique=True)
    destination_kind: Mapped[str] = mapped_column(String(64))
    in_flight: Mapped[bool] = mapped_column(Boolean)

class AgentServiceKey(Base):
    """Hashed, revocable credentials for one actual tenant/service identity."""
    __tablename__ = 'agent_service_keys'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    actor_id: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    active: Mapped[bool] = mapped_column(Boolean)
    expires_at: Mapped[int] = mapped_column(BigInteger)

class OperatorSession(Base):
    """Opaque human session and CSRF hashes; no raw session secrets are stored."""
    __tablename__ = 'operator_sessions'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    tenant_id: Mapped[str] = mapped_column(String(128))
    signing_kid: Mapped[str] = mapped_column(ForeignKey('key_registry.kid'))
    csrf_hash: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean)
    expires_at: Mapped[int] = mapped_column(BigInteger)

class Proposal(Base):
    """Stored strictly validated proposal, bound to its submitting agent tenant."""
    __tablename__ = 'proposals'
    __table_args__=(Index('ix_proposals_tenant_created','tenant_id','created_at','id'),)
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    service_id: Mapped[str] = mapped_column(ForeignKey('agent_service_keys.id'))
    action: Mapped[dict[str, Any]] = mapped_column(JSON)
    action_digest: Mapped[str] = mapped_column(String(71))
    policy_version: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16))
    approved_resource_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_version_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_amount_refunded_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    grant_id: Mapped[str | None] = mapped_column(ForeignKey('grants.id'), nullable=True, unique=True)
    created_at: Mapped[int] = mapped_column(BigInteger)

class ProposalPreview(Base):
    """Server-side evidence of the precise effect viewed by one human session."""
    __tablename__ = 'proposal_previews'
    proposal_id: Mapped[str] = mapped_column(ForeignKey('proposals.id'), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey('operator_sessions.id'), primary_key=True)
    resource_fingerprint: Mapped[str] = mapped_column(String(64))
    action_digest: Mapped[str] = mapped_column(String(71))
    policy_version: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[int] = mapped_column(BigInteger)


class Resource(Base):
    """Provider-sourced absolute payment state; never incremented from webhook deltas."""
    __tablename__ = 'resources'
    id: Mapped[str] = mapped_column(ForeignKey('payments.id'), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    provider_id: Mapped[str] = mapped_column(String(128), unique=True)
    amount_paise: Mapped[int] = mapped_column(BigInteger)
    amount_refunded_paise: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3))
    status: Mapped[str] = mapped_column(String(32))
    version_hash: Mapped[str] = mapped_column(String(64))
    synced_at: Mapped[int] = mapped_column(BigInteger)

class Operation(Base):
    """Durable external refund intent, provider identity, lease and terminal result."""
    __tablename__ = 'operations'
    __table_args__ = (UniqueConstraint('tenant_id','idempotency_key',name='uq_operations_tenant_key'),CheckConstraint("status IN ('PENDING','DONE','FAILED')"),Index('ix_operations_tenant_created','tenant_id','created_at','id'))
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    service_id: Mapped[str] = mapped_column(ForeignKey('agent_service_keys.id'))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_digest: Mapped[str] = mapped_column(String(64))
    grant_jti: Mapped[str] = mapped_column(ForeignKey('grants.id'), unique=True)
    proposal_id: Mapped[str] = mapped_column(ForeignKey('proposals.id'))
    payment_id: Mapped[str] = mapped_column(ForeignKey('payments.id'))
    action: Mapped[dict[str,Any]] = mapped_column(JSON)
    approved_version_hash: Mapped[str] = mapped_column(String(64))
    refunded_before_paise: Mapped[int] = mapped_column(BigInteger)
    policy_version: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict[str,Any]] = mapped_column(JSON)
    created_at: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[int] = mapped_column(BigInteger)
    dispatch_started_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    provider_refund_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_until: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

class WebhookEvent(Base):
    """Verified event deduplication; body hashes also defeat changed header ids."""
    __tablename__ = 'webhook_events'
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    body_hash: Mapped[str] = mapped_column(String(64), unique=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64))
    payment_id: Mapped[str] = mapped_column(String(128))
    received_at: Mapped[int] = mapped_column(BigInteger)


class ReceiptHead(Base):
    """Transactionally locked high-water mark detects deletion of the final receipt."""
    __tablename__ = 'receipt_heads'
    scope: Mapped[str] = mapped_column(String(140), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    receipt_hash: Mapped[str] = mapped_column(String(64))


class SupportChannel(Base):
    """Provisioned public routing identifier; never infer tenant from customer text."""
    __tablename__='support_channels'
    id: Mapped[str] = mapped_column(String(128),primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean)

class IntakeRate(Base):
    """Persistent fixed-window request counters shared by all gateway workers."""
    __tablename__='intake_rates'
    id: Mapped[str] = mapped_column(String(64),primary_key=True)
    window_start: Mapped[int] = mapped_column(BigInteger)
    count: Mapped[int] = mapped_column(BigInteger)

class ModelCall(Base):
    """Bounded model telemetry only: never prompts, outputs or customer text."""
    __tablename__='model_calls'
    __table_args__=(Index('ix_model_calls_tenant_created','tenant_id','created_at','id'),)
    id: Mapped[str] = mapped_column(String(128),primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    ticket_id: Mapped[str] = mapped_column(ForeignKey('tickets.id'))
    service_id: Mapped[str] = mapped_column(ForeignKey('agent_service_keys.id'))
    model: Mapped[str] = mapped_column(String(128))
    input_tokens: Mapped[int | None] = mapped_column(BigInteger,nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(BigInteger,nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(BigInteger,nullable=True)
    latency_ms: Mapped[int] = mapped_column(BigInteger)
    outcome: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[int] = mapped_column(BigInteger)
    claim_token: Mapped[str] = mapped_column(String(128),unique=True)

class RejectedEmail(Base):
    """Durable UID rejection markers prevent malformed mail starving valid intake."""
    __tablename__='rejected_emails'
    id: Mapped[str] = mapped_column(String(64),primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(BigInteger)


class EvalRun(Base):
    """Actual live evaluation results only; no raw tickets, tokens or credentials."""
    __tablename__='eval_runs'
    __table_args__ = (Index('ix_eval_runs_tenant_time', 'tenant_id', 'started_at', 'id'), Index('ix_eval_runs_tenant_status_time', 'tenant_id', 'status', 'started_at', 'id'))
    id: Mapped[str] = mapped_column(String(128),primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    git_sha: Mapped[str | None] = mapped_column(String(64),nullable=True)
    started_at: Mapped[int] = mapped_column(BigInteger)
    finished_at: Mapped[int | None] = mapped_column(BigInteger,nullable=True)
    status: Mapped[str] = mapped_column(String(16))
    summary: Mapped[dict[str,Any]] = mapped_column(JSON)
    cases: Mapped[list[dict[str,Any]]] = mapped_column(JSON)


class ApprovalDispatch(Base):
    """Encrypted, durable single-action human consent handoff; never agent-readable."""
    __tablename__='approval_dispatches'
    __table_args__=(Index('ix_dispatch_queue','status','next_attempt_at','lease_until'),)
    proposal_id: Mapped[str] = mapped_column(ForeignKey('proposals.id'),primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    token_ciphertext: Mapped[str] = mapped_column(String(32768))
    idempotency_key: Mapped[str] = mapped_column(String(128),unique=True)
    status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(64))
    operation_id: Mapped[str | None] = mapped_column(String(128),nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger)
    next_attempt_at: Mapped[int] = mapped_column(BigInteger)
    lease_owner: Mapped[str | None] = mapped_column(String(128),nullable=True)
    lease_until: Mapped[int | None] = mapped_column(BigInteger,nullable=True)
