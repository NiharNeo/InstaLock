"""Business SSO invitations, single-use login state and actual integration requests."""
from alembic import op
import sqlalchemy as sa
revision='0010'
down_revision='0009'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Create empty account tables without seed identities or credentials."""
    op.create_table('sso_identities',sa.Column('email',sa.String(254),primary_key=True),sa.Column('user_id',sa.String(128),sa.ForeignKey('users.id'),nullable=False),sa.Column('signing_kid',sa.String(128),sa.ForeignKey('key_registry.kid'),nullable=False),sa.Column('issuer',sa.String(512),nullable=False),sa.Column('subject',sa.String(255),nullable=True),sa.Column('active',sa.Boolean(),nullable=False))
    op.create_table('sso_attempts',sa.Column('id',sa.String(64),primary_key=True),sa.Column('browser_hash',sa.String(64),nullable=False),sa.Column('nonce',sa.String(128),nullable=False),sa.Column('verifier_ciphertext',sa.String(1024),nullable=False),sa.Column('expires_at',sa.BigInteger(),nullable=False),sa.Column('used',sa.Boolean(),nullable=False))
    op.create_table('integration_requests',sa.Column('tenant_id',sa.String(128),primary_key=True),sa.Column('provider',sa.String(32),primary_key=True),sa.Column('requested_by',sa.String(128),sa.ForeignKey('users.id'),nullable=False),sa.Column('status',sa.String(32),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False))


def downgrade() -> None:
    """Remove business workspace tables after exporting actual account state."""
    op.drop_table('integration_requests')
    op.drop_table('sso_attempts')
    op.drop_table('sso_identities')
