"""Key lifecycle tests use only temporary encrypted fixture key files."""
import base64
import os
import stat
import sys
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.keys import generate_keypair, load_private_key, main, public_key_text, register_public_key, revoke_key
from intentlock.db import KeyRegistry


@pytest.fixture
def fixture_key_file(tmp_path: Any, monkeypatch: Any) -> Any:
    """A dedicated private path/password for fixture-only human key management."""
    path = tmp_path/'fixture-secret.pem'
    monkeypatch.setenv('GRANT_PRIVATE_KEY_FILE',str(path))
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PASSWORD','fixture-secret-password')
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PEM',raising=False)
    return path


def test_generate_encrypted_private_file_public_registry(fixture_context: Any, fixture_key_file: Any) -> None:
    engine = fixture_context[1]
    public = generate_keypair(engine,'fixture-new','human','tenant-a')
    assert stat.S_IMODE(fixture_key_file.stat().st_mode) == 0o600
    assert fixture_key_file.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
    private = load_private_key()
    assert public_key_text(private.public_key()) == public
    with Session(engine) as session:
        record = session.get(KeyRegistry,'fixture-new')
        assert record.public_key == public and record.active
        assert record.operator_id == 'human' and record.tenant_id == 'tenant-a'
        assert record.revoked_at is None
        assert 'PRIVATE KEY' not in str(vars(record))


def test_keyfile_never_overwritten(fixture_context: Any, fixture_key_file: Any) -> None:
    generate_keypair(fixture_context[1],'fixture-first','human','tenant-a')
    original = fixture_key_file.read_bytes()
    with pytest.raises(FileExistsError):
        generate_keypair(fixture_context[1],'fixture-second','human','tenant-a')
    assert fixture_key_file.read_bytes() == original
    with Session(fixture_context[1]) as session:
        assert session.get(KeyRegistry,'fixture-second') is None


def test_key_ids_immutable_even_after_revocation(fixture_context: Any) -> None:
    engine, key = fixture_context[1:3]
    register_public_key(engine,'fixture-kid','human','tenant-a',key.public_key())
    revoke_key(engine,'fixture-kid')
    with pytest.raises(IntegrityError):
        register_public_key(engine,'fixture-kid','human','tenant-a',Ed25519PrivateKey.generate().public_key())
    revoke_key(engine,'fixture-kid') # Revocation retries are idempotent.
    with Session(engine) as session:
        row = session.get(KeyRegistry,'fixture-kid')
        assert not row.active and row.revoked_at is not None


@pytest.mark.parametrize('operator,tenant',[('absent','tenant-a'),('human','tenant-b')])
def test_key_registration_requires_provisioned_human(fixture_context: Any, fixture_key_file: Any, operator: str, tenant: str) -> None:
    with pytest.raises(ValueError,match='active human'):
        generate_keypair(fixture_context[1],'fixture-new',operator,tenant)
    assert not fixture_key_file.exists()


def test_missing_or_ambiguous_key_sources(fixture_key_file: Any, monkeypatch: Any) -> None:
    monkeypatch.delenv('GRANT_PRIVATE_KEY_FILE')
    with pytest.raises(ValueError,match='exactly one'):
        load_private_key()
    monkeypatch.setenv('GRANT_PRIVATE_KEY_FILE',str(fixture_key_file))
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM','fixture-invalid-pem')
    with pytest.raises(ValueError,match='exactly one'):
        load_private_key()


def test_secret_file_permissions_and_symlinks(fixture_context: Any, fixture_key_file: Any, monkeypatch: Any, tmp_path: Any) -> None:
    generate_keypair(fixture_context[1],'fixture-new','human','tenant-a')
    fixture_key_file.chmod(0o644)
    with pytest.raises(ValueError,match='mode'):
        load_private_key()
    fixture_key_file.chmod(0o600)
    link = tmp_path/'fixture-link.pem'
    link.symlink_to(fixture_key_file)
    monkeypatch.setenv('GRANT_PRIVATE_KEY_FILE',str(link))
    with pytest.raises(OSError):
        load_private_key()


def test_key_generation_requires_strong_password(fixture_context: Any, fixture_key_file: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PASSWORD','short')
    with pytest.raises(ValueError,match='16 bytes'):
        generate_keypair(fixture_context[1],'fixture-new','human','tenant-a')
    assert not fixture_key_file.exists()


def test_wrong_password_and_wrong_key_type(fixture_context: Any, fixture_key_file: Any, monkeypatch: Any) -> None:
    generate_keypair(fixture_context[1],'fixture-new','human','tenant-a')
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PASSWORD','wrong-fixture-password')
    with pytest.raises(ValueError):
        load_private_key()
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PASSWORD')
    monkeypatch.delenv('GRANT_PRIVATE_KEY_FILE')
    key = generate_private_key(public_exponent=65537,key_size=2048)
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    with pytest.raises(ValueError,match='Ed25519'):
        load_private_key()


def test_key_management_cli(fixture_context: Any, fixture_key_file: Any, monkeypatch: Any, capsys: Any, tmp_path: Any) -> None:
    monkeypatch.setenv('DATABASE_URL',fixture_context[0].database_url)
    monkeypatch.setattr(sys,'argv',['keys','generate','--kid','fixture-cli','--operator-id','human','--tenant-id','tenant-a'])
    main()
    output = capsys.readouterr().out.strip()
    assert len(base64.b64decode(output,validate=True)) == 32
    assert 'PRIVATE' not in output
    public_file = tmp_path/'fixture-public.pem'
    public_file.write_bytes(load_private_key().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(sys,'argv',['keys','register','--kid','fixture-cli-import','--operator-id','human','--tenant-id','tenant-a','--public-key-file',str(public_file)])
    main()
    monkeypatch.setattr(sys,'argv',['keys','revoke','--kid','fixture-cli'])
    main()
    with Session(fixture_context[1]) as session:
        assert not session.get(KeyRegistry,'fixture-cli').active
        assert session.get(KeyRegistry,'fixture-cli-import').active


def test_revoke_unknown_fails(fixture_context: Any) -> None:
    with pytest.raises(ValueError,match='unknown kid'):
        revoke_key(fixture_context[1],'absent')
