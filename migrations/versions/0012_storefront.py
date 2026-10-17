"""Operator-managed catalog and actual provider-backed storefront orders."""
from alembic import op
import sqlalchemy as sa
revision='0012'
down_revision='0011'
branch_labels=None
depends_on=None


def upgrade() -> None:
    """Create empty commerce tables; no sample business records are seeded."""
    op.create_table('store_products',sa.Column('id',sa.String(64),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('name',sa.String(120),nullable=False),sa.Column('category',sa.String(80),nullable=False),sa.Column('description',sa.String(1000),nullable=False),sa.Column('price_paise',sa.BigInteger(),nullable=False),sa.Column('active',sa.Boolean(),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False))
    op.create_index('ix_store_products_tenant_id','store_products',['tenant_id'])
    op.create_table('store_checkouts',sa.Column('id',sa.String(64),primary_key=True),sa.Column('tenant_id',sa.String(128),nullable=False),sa.Column('channel_id',sa.String(128),sa.ForeignKey('support_channels.id'),nullable=False),sa.Column('shopper_hash',sa.String(64),nullable=False),sa.Column('idempotency_key',sa.String(64),nullable=False),sa.Column('basket_hash',sa.String(64),nullable=False),sa.Column('items',sa.JSON(),nullable=False),sa.Column('amount_paise',sa.BigInteger(),nullable=False),sa.Column('provider_order_id',sa.String(128),nullable=True,unique=True),sa.Column('payment_id',sa.String(128),nullable=True,unique=True),sa.Column('status',sa.String(24),nullable=False),sa.Column('created_at',sa.BigInteger(),nullable=False),sa.Column('paid_at',sa.BigInteger(),nullable=True),sa.UniqueConstraint('tenant_id','shopper_hash','idempotency_key',name='uq_store_checkout_key'))
    op.create_index('ix_store_checkouts_tenant_id','store_checkouts',['tenant_id'])
    op.create_table('store_support_requests',sa.Column('ticket_id',sa.String(128),sa.ForeignKey('tickets.id'),primary_key=True),sa.Column('checkout_id',sa.String(64),sa.ForeignKey('store_checkouts.id'),nullable=False),sa.Column('product_id',sa.String(64),nullable=False),sa.Column('requested_paise',sa.BigInteger(),nullable=False))


def downgrade() -> None:
    """Remove commerce only after exporting real purchases and support associations."""
    op.drop_table('store_support_requests');op.drop_index('ix_store_checkouts_tenant_id',table_name='store_checkouts');op.drop_table('store_checkouts');op.drop_index('ix_store_products_tenant_id',table_name='store_products');op.drop_table('store_products')
