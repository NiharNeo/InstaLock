"""Environment-configured Alembic migrations."""
import os
from alembic import context
from intentlock.db import Base, engine_for

if context.is_offline_mode():
    context.configure(url=os.environ['DATABASE_URL'], target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with engine_for(os.environ['DATABASE_URL']).connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
