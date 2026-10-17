"""Durable encrypted handoff for explicitly approved actions."""
from alembic import op
import sqlalchemy as sa
revision='0009'
down_revision='0008'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Create the empty encrypted grant queue and bounded polling index."""
    op.create_table('approval_dispatches',sa.Column('proposal_id',sa.String(128),sa.ForeignKey('proposals.id'),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('token_ciphertext',sa.String(32768),nullable=False),sa.Column('idempotency_key',sa.String(128),nullable=False,unique=True),sa.Column('status',sa.String(16),nullable=False),sa.Column('reason',sa.String(64),nullable=False),sa.Column('operation_id',sa.String(128),nullable=True),sa.Column('created_at',sa.BigInteger(),nullable=False),sa.Column('next_attempt_at',sa.BigInteger(),nullable=False),sa.Column('lease_owner',sa.String(128),nullable=True),sa.Column('lease_until',sa.BigInteger(),nullable=True))
    for table in ('proposals','operations','model_calls'):
        op.create_index('ix_'+table+'_tenant_created',table,['tenant_id','created_at','id'])
    op.create_index('ix_tickets_tenant_id','tickets',['tenant_id','id'])
    op.create_index('ix_dispatch_queue','approval_dispatches',['status','next_attempt_at','lease_until'])


def downgrade() -> None:
    """Remove the handoff queue only after resolving or exporting queued consent."""
    for table in ('proposals','operations','model_calls'):
        op.drop_index('ix_'+table+'_tenant_created',table_name=table)
    op.drop_index('ix_tickets_tenant_id',table_name='tickets')
    op.drop_index('ix_dispatch_queue',table_name='approval_dispatches')
    op.drop_table('approval_dispatches')
