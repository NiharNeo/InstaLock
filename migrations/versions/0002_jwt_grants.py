"""Public key registry and ACTIVE/USED JWT grant lifecycle."""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Preserve legacy grants as USED and add an empty public key registry."""
    op.create_table(
        'key_registry',
        sa.Column('kid', sa.String(128), primary_key=True),
        sa.Column('public_key', sa.String(128), nullable=False),
        sa.Column('operator_id', sa.String(128), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('tenant_id', sa.String(128), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.BigInteger(), nullable=False),
        sa.Column('revoked_at', sa.BigInteger(), nullable=True),
    )
    # kid is checked against the registry by the service. No ALTER ADD FOREIGN
    # KEY is used: SQLite cannot do it without rebuilding the existing ledger.
    op.add_column('grants', sa.Column('status', sa.String(16), nullable=False, server_default='USED'))
    op.add_column('grants', sa.Column('kid', sa.String(128), nullable=True))
    op.add_column('grants', sa.Column('token_hash', sa.String(64), nullable=True))


def downgrade() -> None:
    """Remove JWT lifecycle columns and registry; back up grants before downgrade."""
    op.drop_column('grants', 'token_hash')
    op.drop_column('grants', 'kid')
    op.drop_column('grants', 'status')
    op.drop_table('key_registry')
