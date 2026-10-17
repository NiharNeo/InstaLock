"""Human-operated provisioning and consent CLI; never run inside an agent."""
import argparse
import base64
import json
import os
import time
from pathlib import Path
from typing import Literal
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field
from sqlalchemy.orm import Session
from intentlock.db import Order, Ticket, User, engine_for
from intentlock.schema import Action, Envelope, Grant, Identifier, Integer, Strict, canonical, digest, parse_json
from intentlock.transport import fetch_json

class UserInput(Strict):
    """Trusted public signing identity imported by an operator."""
    id: Identifier
    tenant_id: Identifier
    public_key: str
    active: bool

class OrderInput(Strict):
    """Real order imported from the source of record."""
    id: Identifier
    tenant_id: Identifier
    paid_paise: Integer
    refunded_paise: int = Field(ge=0, le=9007199254740991)
    currency: Literal['INR']
    destination: Identifier
    version: Integer

class TicketInput(Strict):
    """Actual customer ticket; its body remains untrusted text."""
    id: Identifier
    tenant_id: Identifier
    order_id: Identifier
    text: str = Field(max_length=100000)

def import_records(path: Path) -> None:
    """Insert validated real records atomically; never overwrite trusted state."""
    data = parse_json(path.read_bytes())
    if not isinstance(data, dict) or set(data) != {'users', 'orders', 'tickets'}:
        raise ValueError('expected users, orders, tickets arrays')
    users = [UserInput.model_validate(row) for row in data['users']]
    orders = [OrderInput.model_validate(row) for row in data['orders']]
    tickets = [TicketInput.model_validate(row) for row in data['tickets']]
    for user in users:
        if len(base64.b64decode(user.public_key, validate=True)) != 32:
            raise ValueError('invalid Ed25519 public key')
    with Session(engine_for(os.environ['DATABASE_URL'])) as session, session.begin():
        session.add_all(User(**row.model_dump()) for row in users)
        session.add_all(Order(**row.model_dump()) for row in orders)
        session.flush()
        for row in tickets:
            order = session.get(Order, row.order_id)
            if order is None or order.tenant_id != row.tenant_id:
                raise ValueError('ticket/order tenant mismatch')
            session.add(Ticket(**row.model_dump()))

def main() -> None:
    """Provision real data or explicitly review and sign a live trusted preview."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    imp = commands.add_parser('import')
    imp.add_argument('file', type=Path)
    keygen = commands.add_parser('keygen')
    keygen.add_argument('private_path', type=Path)
    sign = commands.add_parser('sign')
    sign.add_argument('action', type=Path)
    sign.add_argument('--signer-id', required=True)
    sign.add_argument('--grant-id', required=True)
    sign.add_argument('--request-id', required=True)
    sign.add_argument('--ttl', required=True, type=int)
    sign.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'import':
        import_records(args.file)
    elif args.command == 'keygen':
        key = Ed25519PrivateKey.generate()
        password = os.environ['SIGNING_KEY_PASSWORD'].encode()
        if len(password) < 16:
            raise ValueError('key password must be at least 16 characters')
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password))
        fd = os.open(args.private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(pem)
        print(base64.b64encode(key.public_key().public_bytes_raw()).decode())
    else:
        action = Action.model_validate(parse_json(args.action.read_bytes()))
        preview = fetch_json(os.environ['GATEWAY_URL'].rstrip('/') + '/api/preview', os.environ['OPERATOR_TOKEN'], action.model_dump())
        if preview['action_digest'] != digest(action) or preview['action'] != action.model_dump():
            raise ValueError('preview mismatch')
        # Canonical JSON escapes control characters; terminal text cannot inject prompts.
        print(canonical(action).decode())
        print('SHA-256:', digest(action), 'Policy:', preview['policy_version'])
        if input('Review every field above. Type the full SHA-256 to approve: ') != digest(action):
            raise ValueError('human did not approve')
        now = int(time.time())
        grant = Grant(purpose='intentlock.grant.v1', audience='intentlock.gateway', grant_id=args.grant_id, signer_id=args.signer_id, tenant_id=action.tenant_id, action_digest=digest(action), policy_version=preview['policy_version'], issued_at=now, expires_at=now + args.ttl)
        key = serialization.load_pem_private_key(Path(os.environ['SIGNING_KEY_PATH']).read_bytes(), password=os.environ['SIGNING_KEY_PASSWORD'].encode())
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError('Ed25519 key required')
        envelope = Envelope(request_id=args.request_id, action=action, grant=grant, signature=base64.b64encode(key.sign(canonical(grant))).decode())
        with args.output.open('x') as stream:
            stream.write(canonical(envelope).decode() + '\n')

if __name__ == '__main__':
    main()
