"""Trusted real-data provisioning; no public login/bootstrap bypass endpoint."""
import argparse
import json
import os
from pathlib import Path
from typing import Annotated
from pydantic import Field
from sqlalchemy.orm import Session
from app.auth.service import provision_agent, provision_session
from app.core.canonical import _Contract, _load_json
from intentlock.db import Order, Payment, SupportChannel, User, engine_for
from sqlalchemy import select


class PaymentImport(_Contract):
    """An actual source-system payment mapping; only insertions are permitted."""
    id: str = Field(min_length=1,max_length=128)
    tenant_id: str = Field(min_length=1,max_length=128)
    order_id: str = Field(min_length=1,max_length=128)
    destination_kind: str = Field(min_length=1,max_length=64)
    in_flight_refunds: Annotated[int,Field(strict=True,ge=0,le=1)]


def import_payments(session: Session, path: Path) -> None:
    """Insert real mappings after validating the order's tenant; never reset state."""
    data = _load_json(path.read_bytes())
    if not isinstance(data,list):
        raise ValueError('expected a JSON array of actual payment mappings')
    for value in data:
        payment = PaymentImport.model_validate(value)
        order = session.get(Order,payment.order_id)
        if order is None or order.tenant_id != payment.tenant_id:
            raise ValueError('payment/order tenant mismatch')
        session.add(Payment(id=payment.id,tenant_id=payment.tenant_id,order_id=payment.order_id,destination_kind=payment.destination_kind,in_flight=payment.in_flight_refunds == 1))
    session.flush()


def main() -> None:
    """Provision credentials after external human authentication or import actual payments.

    Credential JSON is written to stdout only after a successful DB commit.
    Capture it securely; it is not fixture business data or a login endpoint.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command',required=True)
    agent = commands.add_parser('agent-key')
    agent.add_argument('--service-id',required=True)
    agent.add_argument('--tenant-id',required=True)
    agent.add_argument('--actor-id',required=True)
    agent.add_argument('--ttl',required=True,type=int)
    human = commands.add_parser('operator-session')
    human.add_argument('--operator-id',required=True)
    human.add_argument('--kid',required=True)
    human.add_argument('--ttl',required=True,type=int)
    payments = commands.add_parser('import-payments')
    payments.add_argument('file',type=Path)
    channel=commands.add_parser('support-channel')
    channel.add_argument('--channel-id',required=True)
    channel.add_argument('--tenant-id',required=True)
    args = parser.parse_args()
    engine = engine_for(os.environ['DATABASE_URL'])
    result = None
    try:
        with Session(engine) as session, session.begin():
            if args.command == 'agent-key':
                token = provision_agent(session,args.service_id,args.tenant_id,args.actor_id,args.ttl)
                result = {'agent_service_key':token}
            elif args.command == 'operator-session':
                token,csrf = provision_session(session,args.operator_id,args.kid,args.ttl)
                result = {'session_token':token,'csrf_token':csrf}
            elif args.command=='support-channel':
                if not 1<=len(args.channel_id)<=128 or not session.scalar(select(User.id).where(User.tenant_id==args.tenant_id,User.active.is_(True)).limit(1)):
                    raise ValueError('bounded channel and actual provisioned tenant required')
                session.add(SupportChannel(id=args.channel_id,tenant_id=args.tenant_id,active=True))
            else:
                import_payments(session,args.file)
        if result is not None:
            print(json.dumps(result))
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
