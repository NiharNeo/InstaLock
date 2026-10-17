"""Signed per-tenant receipts; retain historical evidence without re-signing it."""
from alembic import op
import sqlalchemy as sa

revision='0005'
down_revision='0004'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Add chain fields without fabricating tenants/signatures for legacy rows."""
    for name,kind in [('tenant_id',sa.String(128)),('seq',sa.BigInteger()),('decision',sa.String(5)),('reason_code',sa.String(64)),('grant_jti',sa.String(128)),('actor_id',sa.String(128)),('operation_id',sa.String(128)),('created_at',sa.BigInteger()),('prev_hash',sa.String(64)),('receipt_hash',sa.String(64)),('signature',sa.String(128))]:
        op.add_column('receipts',sa.Column(name,kind,nullable=True))
    with op.batch_alter_table('receipts') as batch:
        batch.create_unique_constraint('uq_receipts_tenant_seq',['tenant_id','seq'])
    op.create_table('receipt_heads',sa.Column('scope',sa.String(140),primary_key=True),sa.Column('seq',sa.BigInteger(),nullable=False),sa.Column('receipt_hash',sa.String(64),nullable=False))


def downgrade() -> None:
    """Remove chain metadata only after backing up the signed audit history."""
    op.drop_table('receipt_heads')
    with op.batch_alter_table('receipts') as batch:
        batch.drop_constraint('uq_receipts_tenant_seq',type_='unique')
        for name in ('tenant_id','seq','decision','reason_code','grant_jti','actor_id','operation_id','created_at','prev_hash','receipt_hash','signature'):
            batch.drop_column(name)
