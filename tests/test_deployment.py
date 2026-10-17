"""Migration and configuration checks use isolated fixture databases only."""
import os
import shutil
import subprocess
import sys
from typing import Any
from sqlalchemy import inspect
from intentlock.db import Base, engine_for


def test_alembic_empty_schema_and_metadata(tmp_path: Any) -> None:
    """Apply the immutable migration and compare it to current ORM metadata."""
    url = 'sqlite:///' + str(tmp_path/'fixture-migration.db')
    env = {**os.environ, 'DATABASE_URL':url}
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],env=env,check=True,capture_output=True)
    engine = engine_for(url)
    assert set(inspect(engine).get_table_names()) == set(Base.metadata.tables) | {'alembic_version'}
    subprocess.run([sys.executable,'-m','alembic','check'],env=env,check=True,capture_output=True)
    engine.dispose()


def test_compose_configuration(fixture_context: Any) -> None:
    """Validate Compose interpolation without starting containers or printing tokens."""
    import pytest
    if not shutil.which('docker'):
        pytest.skip('Docker CLI unavailable')
    cfg = fixture_context[0]
    env = {**os.environ, 'DATABASE_URL':cfg.database_url,'GRANT_ISSUER':'fixture-issuer','AGENT_TOKEN':cfg.agent_token,'OPERATOR_TOKEN':cfg.operator_token,'AGENT_TENANT':cfg.agent_tenant,'POLICY_VERSION':cfg.policy_version,'MAX_REFUND_PAISE':str(cfg.max_refund_paise),'MAX_GRANT_SECONDS':str(cfg.max_grant_seconds)}
    subprocess.run(['docker','compose','config','--quiet'],env=env,check=True,capture_output=True)


def test_grant_migration_preserves_consumed_legacy_rows(tmp_path: Any) -> None:
    """An older receipt-linked grant remains USED after adding JWT lifecycle."""
    import json
    from sqlalchemy import text
    url = 'sqlite:///' + str(tmp_path/'fixture-legacy-migration.db')
    env = {**os.environ, 'DATABASE_URL':url}
    subprocess.run([sys.executable,'-m','alembic','upgrade','0001'],env=env,check=True,capture_output=True)
    engine = engine_for(url)
    with engine.begin() as connection:
        connection.execute(text('INSERT INTO grants (id, payload, signature) VALUES (:id, :payload, :signature)'),{'id':'fixture-legacy','payload':json.dumps({'fixture':'legacy'}),'signature':'fixture-signature'})
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],env=env,check=True,capture_output=True)
    with engine.connect() as connection:
        row = connection.execute(text('SELECT status, kid, token_hash, payload, signature FROM grants WHERE id = :id'),{'id':'fixture-legacy'}).one()
        assert row.status == 'USED' and row.kid is None and row.token_hash is None
        assert json.loads(row.payload) == {'fixture':'legacy'} and row.signature == 'fixture-signature'
        assert connection.execute(text('SELECT COUNT(*) FROM key_registry')).scalar() == 0
    engine.dispose()
