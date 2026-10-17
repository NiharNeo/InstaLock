"""Initial immutable empty schema snapshot."""
from alembic import op
import sqlalchemy as sa
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the original schema without importing mutable ORM definitions."""
    op.create_table('users', sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('public_key',sa.String(128),nullable=False),sa.Column('active',sa.Boolean(),nullable=False))
    op.create_table('orders',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('paid_paise',sa.BigInteger(),nullable=False),sa.Column('refunded_paise',sa.BigInteger(),nullable=False),sa.Column('currency',sa.String(3),nullable=False),sa.Column('destination',sa.String(128),nullable=False),sa.Column('version',sa.BigInteger(),nullable=False),sa.CheckConstraint('paid_paise > 0 AND refunded_paise >= 0 AND refunded_paise <= paid_paise'),sa.CheckConstraint('version > 0'))
    op.create_table('tickets',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('order_id',sa.String(128),sa.ForeignKey('orders.id'),nullable=False),sa.Column('text',sa.String(),nullable=False))
    op.create_table('grants',sa.Column('id',sa.String(128),primary_key=True),sa.Column('payload',sa.JSON(),nullable=False),sa.Column('signature',sa.String(128),nullable=False))
    op.create_table('refunds',sa.Column('id',sa.String(128),primary_key=True),sa.Column('grant_id',sa.String(128),sa.ForeignKey('grants.id'),nullable=False,unique=True),sa.Column('order_id',sa.String(128),sa.ForeignKey('orders.id'),nullable=False),sa.Column('amount_paise',sa.BigInteger(),nullable=False),sa.Column('destination',sa.String(128),nullable=False))
    op.create_table('executions',sa.Column('id',sa.String(257),primary_key=True),sa.Column('fingerprint',sa.String(64),nullable=False),sa.Column('result',sa.JSON(),nullable=False))
    op.create_table('receipts',sa.Column('id',sa.String(128),primary_key=True),sa.Column('timestamp',sa.BigInteger(),nullable=False),sa.Column('allowed',sa.Boolean(),nullable=False),sa.Column('reason',sa.String(64),nullable=False),sa.Column('rule_id',sa.String(128),nullable=False),sa.Column('policy_version',sa.String(128),nullable=False),sa.Column('input_hash',sa.String(64),nullable=False),sa.Column('action_digest',sa.String(64)),sa.Column('request_id',sa.String(128)),sa.Column('refund_id',sa.String(128)))


def downgrade() -> None:
    """Remove the initial schema; this intentionally destroys stored records."""
    for table in ('receipts','executions','refunds','grants','tickets','orders','users'):
        op.drop_table(table)
