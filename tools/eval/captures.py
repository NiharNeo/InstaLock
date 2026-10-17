"""Validate capture provenance against actual tickets, grants and webhook receipts."""
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any
import jwt
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.canonical import digest
from app.core.grants import GrantClaims
from intentlock.db import AgentServiceKey, KeyRegistry, Operation, Payment, Proposal, Receipt, Resource, Ticket, UsedGrant, User, WebhookEvent
from tools.eval.contracts import Capture


def claims(token: str) -> dict[str,Any]:
    """Decode for routing only; database and cryptographic checks establish provenance."""
    try:
        return jwt.decode(token,options={'verify_signature':False})
    except jwt.PyJWTError:
        raise ValueError('CAPTURE_GRANT_PROVENANCE') from None


def validate_capture(session: Session,capture: Capture,tenant_id: str) -> None:
    """Reject fabricated/edited captures and require real historical prerequisites."""
    action=capture.action
    ticket=session.get(Ticket,capture.ticket_id)
    proposal=session.get(Proposal,capture.proposal_id)
    payment=session.get(Payment,action.args.payment_id)
    if action.tenant_id!=tenant_id or ticket is None or ticket.tenant_id!=tenant_id or ticket.order_id!=action.resource_ref or payment is None or payment.tenant_id!=tenant_id or payment.order_id!=ticket.order_id:
        raise ValueError('CAPTURE_RESOURCE_PROVENANCE')
    if proposal is None or proposal.tenant_id!=tenant_id or proposal.action_digest!=digest(action) or proposal.action!=action.model_dump(mode='json'):
        raise ValueError('CAPTURE_PROPOSAL_PROVENANCE')
    agent=session.get(AgentServiceKey,proposal.service_id)
    if agent is None or agent.tenant_id!=tenant_id or agent.actor_id!=action.actor_id:
        raise ValueError('CAPTURE_ACTOR_PROVENANCE')
    hint=claims(capture.grant_token)
    row=session.get(UsedGrant,hint['jti'])
    if row is None or row.token_hash!=hashlib.sha256(capture.grant_token.encode()).hexdigest():
        raise ValueError('CAPTURE_GRANT_PROVENANCE')
    registry=session.get(KeyRegistry,row.kid)
    if registry is None or not registry.active or registry.tenant_id!=tenant_id:
        raise ValueError('CAPTURE_KEY_PROVENANCE')
    operator=session.get(User,registry.operator_id)
    if operator is None or not operator.active or operator.tenant_id!=tenant_id:
        raise ValueError('CAPTURE_OPERATOR_PROVENANCE')
    decoded=jwt.decode(capture.grant_token,Ed25519PublicKey.from_public_bytes(base64.b64decode(registry.public_key,validate=True)),algorithms=['EdDSA'],options={'verify_exp':False,'verify_iat':False,'verify_aud':False})
    verified=GrantClaims.model_validate(decoded)
    if decoded!=row.payload or verified.tid!=tenant_id or row.expires_at!=verified.exp:
        raise ValueError('CAPTURE_CLAIMS_PROVENANCE')
    if capture.role=='different_tool':
        other=capture.other_tool_action
        if other is None or other.get('tool') in (None,'refund.create') or {**other,'tool':'refund.create'}!=action.model_dump(mode='json') or verified.act_digest!='sha256:'+hashlib.sha256(rfc8785.dumps(other)).hexdigest():
            raise ValueError('OTHER_TOOL_GRANT_REQUIRED')
    elif proposal.grant_id!=verified.jti or verified.act_digest!=digest(action):
        raise ValueError('CAPTURE_APPROVAL_PROVENANCE')
    if capture.role=='used':
        if row.status!='USED' or session.scalar(select(Operation.id).where(Operation.grant_jti==verified.jti,Operation.status=='DONE')) is None:
            raise ValueError('REAL_USED_GRANT_REQUIRED')
    elif row.status!='ACTIVE':
        raise ValueError('ACTIVE_CAPTURE_GRANT_REQUIRED')
    if capture.role=='stale':
        event=session.get(WebhookEvent,capture.webhook_event_id) if capture.webhook_event_id else None
        resource=session.get(Resource,payment.id)
        approved=session.scalar(select(Receipt).where(Receipt.tenant_id==tenant_id,Receipt.request_id==proposal.id,Receipt.reason_code=='APPROVED'))
        applied=session.scalar(select(Receipt).where(Receipt.tenant_id==tenant_id,Receipt.input_hash==event.body_hash,Receipt.reason_code=='WEBHOOK_APPLIED')) if event else None
        if event is None or event.tenant_id!=tenant_id or event.payment_id!=payment.id or resource is None or resource.version_hash==proposal.approved_version_hash or approved is None or applied is None or applied.seq<=approved.seq:
            raise ValueError('REAL_POST_APPROVAL_WEBHOOK_REQUIRED')


def write_secret(path: Path,value: dict[str,Any]) -> None:
    """Create a capture file atomically without overwrite or world-readable secrets."""
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,ensure_ascii=False,separators=(',',':'))
        stream.write('\n')


def read_secret(path: Path) -> bytes:
    """Read a bounded private regular file; never follow a final symlink."""
    import stat
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        mode=os.fstat(stream.fileno())
        if not stat.S_ISREG(mode.st_mode) or mode.st_mode&0o077:
            raise ValueError('protected 0600/0400 capture required')
        raw=stream.read(4194305)
    if len(raw)>4194304:
        raise ValueError('capture too large')
    return raw
