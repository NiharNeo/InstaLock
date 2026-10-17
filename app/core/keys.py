"""Human-operated Ed25519 key management; private keys never enter the database."""
from __future__ import annotations

import argparse
import base64
import os
import stat
import time
from pathlib import Path
from typing import Annotated

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.canonical import _Contract
from intentlock.db import KeyRegistry, User, engine_for


class KeyIdentity(_Contract):
    """Explicit immutable key ownership supplied by a trusted human operator."""
    kid: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    operator_id: Annotated[str, Field(strict=True, min_length=1, max_length=128)]
    tenant_id: Annotated[str, Field(strict=True, min_length=1, max_length=128)]


def public_key_text(key: Ed25519PublicKey) -> str:
    """Encode a raw Ed25519 public key for database storage."""
    return base64.b64encode(key.public_bytes_raw()).decode('ascii')


def _deserialize_private_key(pem: bytes, password: str | None) -> Ed25519PrivateKey:
    if len(pem) > 16384:
        raise ValueError('private key PEM is too large')
    key = serialization.load_pem_private_key(pem,password=password.encode() if password else None)
    if not isinstance(key,Ed25519PrivateKey):
        raise ValueError('Ed25519 private key required')
    return key


def load_private_key_file(path: str, password: str | None = None) -> Ed25519PrivateKey:
    """Read a protected regular secret file without following a final symlink."""
    fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ValueError('secret key file requires mode 0600 or 0400')
        return _deserialize_private_key(stream.read(16385),password)


def load_private_key() -> Ed25519PrivateKey:
    """Load exactly one environment PEM or protected private secret file."""
    pem_env = os.environ.get('GRANT_PRIVATE_KEY_PEM')
    file_env = os.environ.get('GRANT_PRIVATE_KEY_FILE')
    if bool(pem_env) == bool(file_env):
        raise ValueError('configure exactly one grant private key source')
    password = os.environ.get('GRANT_PRIVATE_KEY_PASSWORD')
    if file_env:
        return load_private_key_file(file_env,password)
    assert pem_env is not None
    return _deserialize_private_key(pem_env.encode('utf-8'),password)


def load_private_key_for_kid(kid: str) -> Ed25519PrivateKey:
    """Resolve a trusted registered signing kid through an environment file map.

    GRANT_KEY_FILE_MAP is a JSON mapping from registry kids to protected mounted
    file paths, not private material. It supports concurrent multi-tenant human
    issuers without mutating process environment between requests. Configure this
    map OR the single-key environment/file source, never both.
    """
    from app.core.canonical import _load_json
    configured = os.environ.get('GRANT_KEY_FILE_MAP')
    if not configured:
        return load_private_key()
    if os.environ.get('GRANT_PRIVATE_KEY_PEM') or os.environ.get('GRANT_PRIVATE_KEY_FILE'):
        raise ValueError('ambiguous gateway signing key configuration')
    paths = _load_json(configured)
    if not isinstance(paths,dict) or not all(isinstance(key,str) and isinstance(path,str) and path for key,path in paths.items()) or kid not in paths:
        raise ValueError('unknown signing kid in secret file map')
    return load_private_key_file(paths[kid],os.environ.get('GRANT_PRIVATE_KEY_PASSWORD'))


def register_public_key(engine: Engine, kid: str, operator_id: str, tenant_id: str, public_key: Ed25519PublicKey) -> None:
    """Insert a new immutable kid for a provisioned, active human in that tenant."""
    identity = KeyIdentity(kid=kid, operator_id=operator_id, tenant_id=tenant_id)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError('Ed25519 public key required')
    with Session(engine) as session, session.begin():
        user = session.get(User, identity.operator_id)
        if user is None or not user.active or user.tenant_id != identity.tenant_id:
            raise ValueError('active human operator in the same tenant required')
        session.add(KeyRegistry(**identity.model_dump(), public_key=public_key_text(public_key), active=True, created_at=int(time.time()), revoked_at=None))


def generate_keypair(engine: Engine, kid: str, operator_id: str, tenant_id: str) -> str:
    """Generate an encrypted private secret file and register only its public key.

    A fresh kid rotates signing keys without revoking old kids. File creation is
    exclusive and mode 0600. If registration fails, the encrypted file is retained
    for recovery; it is never silently overwritten or deleted.
    """
    KeyIdentity(kid=kid, operator_id=operator_id, tenant_id=tenant_id)
    path = Path(os.environ['GRANT_PRIVATE_KEY_FILE'])
    if os.environ.get('GRANT_PRIVATE_KEY_PEM'):
        raise ValueError('ambiguous private key sources')
    password = os.environ['GRANT_PRIVATE_KEY_PASSWORD'].encode()
    if len(password) < 16:
        raise ValueError('private key password must have at least 16 bytes')
    # Verify the operator before creating any secret material on disk.
    with Session(engine) as session:
        user = session.get(User, operator_id)
        if user is None or not user.active or user.tenant_id != tenant_id:
            raise ValueError('active human operator in the same tenant required')
        if session.get(KeyRegistry, kid) is not None:
            raise ValueError('kid already exists; use a fresh kid for rotation')
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(pem)
    register_public_key(engine, kid, operator_id, tenant_id, key.public_key())
    return public_key_text(key.public_key())


def revoke_key(engine: Engine, kid: str) -> None:
    """Permanently revoke an existing kid; no CLI operation reactivates it."""
    with Session(engine) as session, session.begin():
        registry = session.get(KeyRegistry, kid)
        if registry is None:
            raise ValueError('unknown kid')
        if registry.active:
            session.execute(update(KeyRegistry).where(KeyRegistry.kid == kid, KeyRegistry.active.is_(True)).values(active=False, revoked_at=int(time.time())))


def main() -> None:
    """Generate/register/revoke public keys from a trusted operator workstation."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('generate', 'register'):
        subparser = commands.add_parser(command)
        subparser.add_argument('--kid', required=True)
        subparser.add_argument('--operator-id', required=True)
        subparser.add_argument('--tenant-id', required=True)
        if command == 'register':
            subparser.add_argument('--public-key-file', required=True, type=Path)
    revoke = commands.add_parser('revoke')
    revoke.add_argument('--kid', required=True)
    args = parser.parse_args()
    engine = engine_for(os.environ['DATABASE_URL'])
    try:
        if args.command == 'generate':
            print(generate_keypair(engine, args.kid, args.operator_id, args.tenant_id))
        elif args.command == 'register':
            key = serialization.load_pem_public_key(args.public_key_file.read_bytes())
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError('Ed25519 public key required')
            register_public_key(engine, args.kid, args.operator_id, args.tenant_id, key)
        else:
            revoke_key(engine, args.kid)
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
