"""Real payment timestamps, ticket timing and append-only business policies."""
from alembic import op
import sqlalchemy as sa
revision='0011'
down_revision='0010'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Leave unknown historic timestamps NULL rather than inventing business history."""
    op.add_column('resources',sa.Column('payment_created_at',sa.BigInteger(),nullable=True))
    op.add_column('tickets',sa.Column('created_at',sa.BigInteger(),nullable=True))
    op.create_table('business_refund_policies',sa.Column('tenant_id',sa.String(128),primary_key=True),sa.Column('revision_id',sa.String(64),nullable=False))
    op.create_table('refund_policy_revisions',sa.Column('id',sa.String(64),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('rules',sa.JSON(),nullable=False),sa.Column('content_hash',sa.String(71),nullable=False),sa.Column('created_by',sa.String(128),sa.ForeignKey('users.id'),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False))
    op.create_index('ix_refund_policy_revisions_tenant_id','refund_policy_revisions',['tenant_id'])


def downgrade() -> None:
    """Remove new metadata after exporting real policy history."""
    op.drop_index('ix_refund_policy_revisions_tenant_id',table_name='refund_policy_revisions')
    op.drop_table('refund_policy_revisions');op.drop_table('business_refund_policies')
    op.drop_column('tickets','created_at');op.drop_column('resources','payment_created_at')
