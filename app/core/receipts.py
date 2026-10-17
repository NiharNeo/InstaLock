"""Signed append-only decision evidence with independent tenant hash chains."""
from __future__ import annotations
import argparse
import base64
import hashlib
import os
import time
from pathlib import Path
from typing import Any
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.canonical import MAX_SAFE_INTEGER
from app.core.keys import _deserialize_private_key, load_private_key_file
from intentlock.db import KeyRegistry, Receipt, ReceiptHead

GENESIS='0'*64
# Legacy metadata remains signed too: editing any persisted receipt field is detected.
FIELDS=('id','tenant_id','seq','decision','reason_code','rule_id','policy_version','action_digest','grant_jti','actor_id','operation_id','created_at','prev_hash','timestamp','allowed','reason','input_hash','request_id','refund_id')


def load_receipt_key() -> Ed25519PrivateKey:
    """Load a dedicated persistent key; missing/ambiguous secrets fail closed."""
    pem,path=os.environ.get('RECEIPT_PRIVATE_KEY_PEM'),os.environ.get('RECEIPT_PRIVATE_KEY_FILE')
    if bool(pem)==bool(path):
        raise ValueError('configure exactly one dedicated receipt private key source')
    password=os.environ.get('RECEIPT_PRIVATE_KEY_PASSWORD')
    key=load_private_key_file(path,password) if path else _deserialize_private_key(pem.encode(),password)
    # Refuse accidental reuse of a single configured human authorization key.
    if os.environ.get('GRANT_PRIVATE_KEY_PEM') or os.environ.get('GRANT_PRIVATE_KEY_FILE'):
        from app.core.keys import load_private_key
        try:
            grant_key=load_private_key()
        except (ValueError,OSError,TypeError):
            grant_key=None  # Receipt auditing must survive broken grant configuration.
        if grant_key is not None and key.public_key().public_bytes_raw()==grant_key.public_key().public_bytes_raw():
            raise ValueError('receipt and grant signing keys must differ')
    return key


def payload(row: Receipt) -> dict[str,Any]:
    """Return the complete signed field whitelist, excluding hash and signature."""
    return {name:getattr(row,name) for name in FIELDS}


def serialize_receipt(row: Receipt) -> dict[str,Any]:
    """Expose only structured decision metadata, never customer ticket contents."""
    return {**payload(row),'receipt_hash':row.receipt_hash,'signature':row.signature}


def reserve_audit_transaction(session: Session) -> None:
    """Acquire SQLite's writer slot before authentication reads in audited read endpoints.

    This portable zero-row UPDATE changes no receipt. PostgreSQL takes no row lock;
    SQLite reserves its single writer up front, avoiding read-to-write deadlocks
    when several browser tabs authenticate and append read-decision receipts.
    """
    session.execute(update(ReceiptHead).where(ReceiptHead.scope.is_(None)).values(seq=ReceiptHead.seq))


def append_receipt(session: Session, *, tenant_id: str | None = None, actor_id: str | None = None, grant_jti: str | None = None, operation_id: str | None = None, **metadata: Any) -> Receipt:
    """Lock the tenant head and append signed evidence in the caller's transaction.

    NULL tenant means an unauthenticated system event, never a guessed tenant.
    No commit occurs here. Sequence allocation and signatures roll back together.
    """
    system=metadata.pop('_system',False)
    key=load_receipt_key()
    tenant_id=tenant_id if tenant_id is not None or system else session.info.get('receipt_tenant')
    actor_id=actor_id if actor_id is not None else session.info.get('receipt_actor')
    scope='tenant:'+tenant_id if tenant_id is not None else 'system:unscoped'
    # First SQL is a write: serialize SQLite before establishing a read snapshot.
    session.execute(update(ReceiptHead).where(ReceiptHead.scope==scope).values(seq=ReceiptHead.seq))
    public=base64.b64encode(key.public_key().public_bytes_raw()).decode('ascii')
    if session.scalar(select(KeyRegistry.kid).where(KeyRegistry.public_key==public).limit(1)) is not None:
        raise ValueError('receipt key must not be a registered grant key')
    head=session.scalar(select(ReceiptHead).where(ReceiptHead.scope==scope).with_for_update())
    if head is None:
        try:
            with session.begin_nested():
                session.add(ReceiptHead(scope=scope,seq=0,receipt_hash=GENESIS))
                session.flush()
        except IntegrityError:
            pass
        head=session.scalar(select(ReceiptHead).where(ReceiptHead.scope==scope).with_for_update())
    if head is None or head.seq>=MAX_SAFE_INTEGER:
        raise ValueError('invalid receipt chain head')
    condition=Receipt.tenant_id==tenant_id if tenant_id is not None else Receipt.tenant_id.is_(None)
    if head.seq:
        tail=session.scalar(select(Receipt).where(condition,Receipt.seq==head.seq))
        if tail is None or tail.receipt_hash!=head.receipt_hash or hashlib.sha256(rfc8785.dumps(payload(tail))).hexdigest()!=head.receipt_hash:
            raise ValueError('receipt tail was removed or changed')
        key.public_key().verify(base64.b64decode(tail.signature,validate=True),bytes.fromhex(tail.receipt_hash))
    timestamp=metadata.setdefault('timestamp',int(time.time()))
    row=Receipt(**metadata,tenant_id=tenant_id,actor_id=actor_id,grant_jti=grant_jti,operation_id=operation_id,seq=head.seq+1,decision='ALLOW' if metadata['allowed'] else 'DENY',reason_code=metadata['reason'],created_at=timestamp,prev_hash=head.receipt_hash)
    row.receipt_hash=hashlib.sha256(rfc8785.dumps(payload(row))).hexdigest()
    row.signature=base64.b64encode(key.sign(bytes.fromhex(row.receipt_hash))).decode('ascii')
    session.add(row)
    head.seq=row.seq
    head.receipt_hash=row.receipt_hash
    session.flush()
    return row


def verify_chain(session: Session, tenant_id: str | None) -> dict[str,Any]:
    """Walk every link/signature and check the head to detect middle/tail deletion.

    The head is locked before reading receipts for a consistent concurrent view.
    A database-plus-head rollback needs an externally retained trusted checkpoint.
    """
    scope='tenant:'+tenant_id if tenant_id is not None else 'system:unscoped'
    session.execute(update(ReceiptHead).where(ReceiptHead.scope==scope).values(seq=ReceiptHead.seq))
    head=session.scalar(select(ReceiptHead).where(ReceiptHead.scope==scope).with_for_update())
    key=load_receipt_key().public_key()
    condition=Receipt.tenant_id==tenant_id if tenant_id is not None else Receipt.tenant_id.is_(None)
    expected,previous=1,GENESIS
    def broken(reason: str, seq: int, identifier: str | None = None) -> dict[str,Any]:
        return {'valid':False,'reason':reason,'first_broken_seq':seq,'receipt_id':identifier,'checked':expected-1}
    for row in session.scalars(select(Receipt).where(condition).order_by(Receipt.seq).execution_options(yield_per=500)):
        if row.seq!=expected:
            return broken('SEQUENCE_GAP' if row.seq is not None else 'LEGACY_UNSIGNED',expected,row.id)
        if row.prev_hash!=previous:
            return broken('PREV_HASH_MISMATCH',expected,row.id)
        try:
            computed=hashlib.sha256(rfc8785.dumps(payload(row))).hexdigest()
            if computed!=row.receipt_hash:
                return broken('RECEIPT_HASH_MISMATCH',expected,row.id)
            key.verify(base64.b64decode(row.signature,validate=True),bytes.fromhex(computed))
        except Exception:
            return broken('BAD_RECEIPT_SIGNATURE',expected,row.id)
        previous=row.receipt_hash
        expected+=1
    if head is None:
        if expected!=1:
            return broken('HEAD_MISSING',expected)
    elif head.seq!=expected-1 or head.receipt_hash!=previous:
        return broken('HEAD_MISMATCH',expected)
    return {'valid':True,'reason':'CHAIN_VALID','checked':expected-1,'head_seq':expected-1,'head_hash':previous,'first_broken_seq':None}


def main() -> None:
    """Generate a new dedicated receipt key into a protected, non-overwritten file."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    key=Ed25519PrivateKey.generate()
    raw=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw)
    print(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode(),end='')


if __name__=='__main__':
    main()
