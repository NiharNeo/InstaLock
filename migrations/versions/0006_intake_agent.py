"""Public intake, redacted ticket leases and model telemetry; no seed records."""
from alembic import op
import sqlalchemy as sa

revision='0006'
down_revision='0005'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Retain imported raw text; mask it lazily before the first agent read."""
    with op.batch_alter_table('tickets') as batch:
        batch.alter_column('order_id',existing_type=sa.String(128),nullable=True)
        for name,kind in [('redacted_text',sa.String()),('source_id',sa.String(64)),('claimed_by',sa.String(128)),('claim_token',sa.String(128)),('lease_until',sa.BigInteger())]:
            batch.add_column(sa.Column(name,kind,nullable=True))
        batch.add_column(sa.Column('processing_status',sa.String(16),nullable=False,server_default='QUEUED'))
        batch.create_unique_constraint('uq_tickets_source_id',['source_id'])
    op.create_table('rejected_emails',sa.Column('id',sa.String(64),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('reason',sa.String(64),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False))
    op.create_table('support_channels',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('active',sa.Boolean(),nullable=False))
    op.create_table('intake_rates',sa.Column('id',sa.String(64),primary_key=True),sa.Column('window_start',sa.BigInteger(),nullable=False),sa.Column('count',sa.BigInteger(),nullable=False))
    op.create_table('model_calls',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('ticket_id',sa.String(128),sa.ForeignKey('tickets.id'),nullable=False),sa.Column('service_id',sa.String(128),sa.ForeignKey('agent_service_keys.id'),nullable=False),sa.Column('model',sa.String(128),nullable=False),sa.Column('input_tokens',sa.BigInteger(),nullable=True),sa.Column('output_tokens',sa.BigInteger(),nullable=True),sa.Column('total_tokens',sa.BigInteger(),nullable=True),sa.Column('latency_ms',sa.BigInteger(),nullable=False),sa.Column('outcome',sa.String(32),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False),sa.Column('claim_token',sa.String(128),nullable=False,unique=True))


def downgrade() -> None:
    """Require a backup/explicit relinking before removing nullable ticket associations."""
    op.drop_table('model_calls')
    op.drop_table('rejected_emails')
    op.drop_table('intake_rates')
    op.drop_table('support_channels')
    with op.batch_alter_table('tickets') as batch:
        batch.drop_constraint('uq_tickets_source_id',type_='unique')
        for name in ('redacted_text','source_id','claimed_by','claim_token','lease_until','processing_status'):
            batch.drop_column(name)
        batch.alter_column('order_id',existing_type=sa.String(128),nullable=False)
