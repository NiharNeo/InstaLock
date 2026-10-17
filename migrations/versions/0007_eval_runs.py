"""Persist actual live-stack evaluation evidence without secret capture artifacts."""
from alembic import op
import sqlalchemy as sa
revision='0007'
down_revision='0006'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Create empty tenant-scoped evaluation history."""
    op.create_table('eval_runs',sa.Column('id',sa.String(128),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('git_sha',sa.String(64),nullable=True),sa.Column('started_at',sa.BigInteger(),nullable=False),sa.Column('finished_at',sa.BigInteger(),nullable=True),sa.Column('status',sa.String(16),nullable=False),sa.Column('summary',sa.JSON(),nullable=False),sa.Column('cases',sa.JSON(),nullable=False))


def downgrade() -> None:
    """Remove evaluation history only after exporting actual evidence."""
    op.drop_table('eval_runs')
