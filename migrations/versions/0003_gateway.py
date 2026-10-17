"""Real payment mappings, tenant credentials, proposals, and reviewed effects."""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create empty gateway workflow tables; import actual records explicitly."""
    op.create_table('payments',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('order_id',sa.String(128),sa.ForeignKey('orders.id'),nullable=False,unique=True),sa.Column('destination_kind',sa.String(64),nullable=False),sa.Column('in_flight',sa.Boolean(),nullable=False))
    op.create_table('agent_service_keys',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('actor_id',sa.String(128),nullable=False),sa.Column('token_hash',sa.String(64),nullable=False,unique=True),sa.Column('active',sa.Boolean(),nullable=False),sa.Column('expires_at',sa.BigInteger(),nullable=False))
    op.create_table('operator_sessions',sa.Column('id',sa.String(64),primary_key=True),sa.Column('user_id',sa.String(128),sa.ForeignKey('users.id'),nullable=False),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('signing_kid',sa.String(128),sa.ForeignKey('key_registry.kid'),nullable=False),sa.Column('csrf_hash',sa.String(64),nullable=False),sa.Column('active',sa.Boolean(),nullable=False),sa.Column('expires_at',sa.BigInteger(),nullable=False))
    op.create_table('proposals',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('service_id',sa.String(128),sa.ForeignKey('agent_service_keys.id'),nullable=False),sa.Column('action',sa.JSON(),nullable=False),sa.Column('action_digest',sa.String(71),nullable=False),sa.Column('policy_version',sa.String(128),nullable=False),sa.Column('status',sa.String(16),nullable=False),sa.Column('approved_resource_fingerprint',sa.String(64),nullable=True),sa.Column('grant_id',sa.String(128),sa.ForeignKey('grants.id'),nullable=True,unique=True),sa.Column('created_at',sa.BigInteger(),nullable=False))
    op.create_table('proposal_previews',sa.Column('proposal_id',sa.String(128),sa.ForeignKey('proposals.id'),primary_key=True),sa.Column('session_id',sa.String(64),sa.ForeignKey('operator_sessions.id'),primary_key=True),sa.Column('resource_fingerprint',sa.String(64),nullable=False),sa.Column('action_digest',sa.String(71),nullable=False),sa.Column('policy_version',sa.String(128),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False))


def downgrade() -> None:
    """Remove workflow and credential tables; back up live data first."""
    for table in ('proposal_previews','proposals','operator_sessions','agent_service_keys','payments'):
        op.drop_table(table)
