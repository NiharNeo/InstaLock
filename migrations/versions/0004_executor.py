"""Durable provider resources, strict grant expiry and external refund operations."""
from alembic import op
import sqlalchemy as sa
import json

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Preserve issued grants and add empty provider-backed executor tables."""
    op.add_column('grants',sa.Column('expires_at',sa.BigInteger(),nullable=True))
    grants = sa.table('grants',sa.column('id',sa.String()),sa.column('payload',sa.JSON()),sa.column('status',sa.String()),sa.column('expires_at',sa.BigInteger()))
    # Portable backfill from actual stored JWT payloads, not synthetic grant data.
    connection = op.get_bind()
    for row in connection.execute(sa.select(grants.c.id,grants.c.payload,grants.c.status)):
        payload = json.loads(row.payload) if isinstance(row.payload,str) else row.payload
        expiry = payload.get('exp') if isinstance(payload,dict) else None
        if type(expiry) is int and 0<expiry<=9007199254740991:
            connection.execute(grants.update().where(grants.c.id==row.id).values(expires_at=expiry))
        elif row.status == 'ACTIVE':
            connection.execute(grants.update().where(grants.c.id==row.id).values(status='USED'))
    op.add_column('proposals',sa.Column('approved_version_hash',sa.String(64),nullable=True))
    op.add_column('proposals',sa.Column('approved_amount_refunded_paise',sa.BigInteger(),nullable=True))
    op.create_table('resources',sa.Column('id',sa.String(128),sa.ForeignKey('payments.id'),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('provider_id',sa.String(128),nullable=False,unique=True),sa.Column('amount_paise',sa.BigInteger(),nullable=False),sa.Column('amount_refunded_paise',sa.BigInteger(),nullable=False),sa.Column('currency',sa.String(3),nullable=False),sa.Column('status',sa.String(32),nullable=False),sa.Column('version_hash',sa.String(64),nullable=False),sa.Column('synced_at',sa.BigInteger(),nullable=False))
    op.create_table('operations',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('service_id',sa.String(128),sa.ForeignKey('agent_service_keys.id'),nullable=False),sa.Column('idempotency_key',sa.String(128),nullable=False),sa.Column('request_digest',sa.String(64),nullable=False),sa.Column('grant_jti',sa.String(128),sa.ForeignKey('grants.id'),nullable=False,unique=True),sa.Column('proposal_id',sa.String(128),sa.ForeignKey('proposals.id'),nullable=False),sa.Column('payment_id',sa.String(128),sa.ForeignKey('payments.id'),nullable=False),sa.Column('action',sa.JSON(),nullable=False),sa.Column('approved_version_hash',sa.String(64),nullable=False),sa.Column('refunded_before_paise',sa.BigInteger(),nullable=False),sa.Column('policy_version',sa.String(128),nullable=False),sa.Column('status',sa.String(16),nullable=False),sa.Column('reason',sa.String(64),nullable=False),sa.Column('result',sa.JSON(),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False),sa.Column('updated_at',sa.BigInteger(),nullable=False),sa.Column('dispatch_started_at',sa.BigInteger(),nullable=True),sa.Column('provider_refund_id',sa.String(128),nullable=True,unique=True),sa.Column('lease_owner',sa.String(128),nullable=True),sa.Column('lease_until',sa.BigInteger(),nullable=True),sa.UniqueConstraint('tenant_id','idempotency_key',name='uq_operations_tenant_key'),sa.CheckConstraint("status IN ('PENDING','DONE','FAILED')"))
    op.create_table('webhook_events',sa.Column('id',sa.String(128),primary_key=True),sa.Column('body_hash',sa.String(64),nullable=False,unique=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('event_type',sa.String(64),nullable=False),sa.Column('payment_id',sa.String(128),nullable=False),sa.Column('received_at',sa.BigInteger(),nullable=False))


def downgrade() -> None:
    """Remove external execution metadata only after backing up live operations."""
    for name in ('webhook_events','operations','resources'):
        op.drop_table(name)
    op.drop_column('proposals','approved_amount_refunded_paise')
    op.drop_column('proposals','approved_version_hash')
    op.drop_column('grants','expires_at')
