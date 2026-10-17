"""Durable public ticket intake and per-client rate limits."""
import hashlib
import hmac
import os
import time
from typing import Any
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.errors import GatewayDenied
from app.core.receipts import append_receipt
from app.intake.redaction import redact
from intentlock.db import IntakeRate, Order, SupportChannel, Ticket

MAX_TEXT=16000
MAX_BODY=65536


class TicketInput(BaseModel):
    """Public routing and optional untrusted order reference; no tenant parameter."""
    model_config=ConfigDict(strict=True,extra="forbid")
    channel_id: str = Field(min_length=1,max_length=128)
    order_id: str | None = Field(default=None,min_length=1,max_length=128)
    text: str = Field(min_length=1,max_length=MAX_TEXT)


def rate_limit(session: Session, client_ip: str, *, now: int | None = None) -> None:
    """Atomically count the socket peer (never spoofable forwarded headers)."""
    secret=os.environ['INTAKE_RATE_SECRET']
    if len(secret)<32:
        raise ValueError('strong intake rate HMAC secret required')
    current=int(time.time()) if now is None else now
    identifier=hmac.new(secret.encode(),client_ip.encode(),hashlib.sha256).hexdigest()
    session.execute(update(IntakeRate).where(IntakeRate.id==identifier).values(count=IntakeRate.count))
    row=session.scalar(select(IntakeRate).where(IntakeRate.id==identifier).with_for_update())
    if row is None:
        try:
            with session.begin_nested():
                session.add(IntakeRate(id=identifier,window_start=current,count=0))
                session.flush()
        except IntegrityError:
            pass
        row=session.scalar(select(IntakeRate).where(IntakeRate.id==identifier).with_for_update())
    assert row is not None
    if current>=row.window_start+60:
        row.window_start=current
        row.count=0
    if row.count>=10:
        raise GatewayDenied('RATE_LIMITED','intake.rate_limit',429)
    row.count+=1


def create_ticket(session: Session, body: TicketInput, policy_version: str, *, source_id: str | None = None) -> dict[str,Any]:
    """Store real raw and masked content; only existing tenant orders can be linked."""
    session.execute(update(SupportChannel).where(SupportChannel.id==body.channel_id).values(active=SupportChannel.active))
    channel=session.get(SupportChannel,body.channel_id)
    if channel is None or not channel.active:
        raise GatewayDenied('INTAKE_CHANNEL_UNAVAILABLE','intake.channel',404)
    if not body.text.strip():
        raise GatewayDenied('INVALID_REQUEST','intake.empty_text',400)
    order=session.get(Order,body.order_id) if body.order_id else None
    # Unknown/cross-tenant IDs remain unlinked; do not expose an order-existence oracle.
    order_id=order.id if order is not None and order.tenant_id==channel.tenant_id else None
    identifier=str(uuid4())
    session.add(Ticket(id=identifier,tenant_id=channel.tenant_id,order_id=order_id,text=body.text,redacted_text=redact(body.text),source_id=source_id,processing_status='QUEUED',created_at=int(time.time())))
    row=append_receipt(session,tenant_id=channel.tenant_id,id=str(uuid4()),timestamp=int(time.time()),allowed=True,reason='TICKET_ACCEPTED',rule_id='intake.accept',policy_version=policy_version,input_hash=hashlib.sha256(body.text.encode()).hexdigest(),action_digest=None,request_id=identifier,refund_id=None)
    return {'allowed':True,'reason':'TICKET_ACCEPTED','rule_id':'intake.accept','policy_version':policy_version,'ticket_id':identifier,'receipt_id':row.id}
