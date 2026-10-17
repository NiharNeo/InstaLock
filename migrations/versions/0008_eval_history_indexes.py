"""Bound tenant history scans for both unfiltered and status-filtered pagination."""
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Index the actual tenant-scoped history query order."""
    op.create_index('ix_eval_runs_tenant_time', 'eval_runs', ['tenant_id', 'started_at', 'id'])
    op.create_index('ix_eval_runs_tenant_status_time', 'eval_runs', ['tenant_id', 'status', 'started_at', 'id'])


def downgrade() -> None:
    """Remove pagination indexes while preserving all evaluation evidence."""
    op.drop_index('ix_eval_runs_tenant_status_time', table_name='eval_runs')
    op.drop_index('ix_eval_runs_tenant_time', table_name='eval_runs')
