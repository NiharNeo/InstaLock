"""Optional trusted IMAP intake: read-only TLS, durable UID deduplication, no sending."""
import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import imaplib
import os
from pathlib import Path
import re
import ssl
import time
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine
from app.core.policy import PolicyEngine
from app.core.receipts import append_receipt, load_receipt_key
from app.intake.service import TicketInput, create_ticket
from intentlock.db import RejectedEmail, SupportChannel, Ticket, engine_for
from uuid import uuid4

MAX_EMAIL=262144


def email_text(raw: bytes) -> str:
    """Read bounded plain-text MIME only; never process attachments or active HTML."""
    if len(raw)>MAX_EMAIL:
        raise ValueError('EMAIL_TOO_LARGE')
    message=BytesParser(policy=policy.default).parsebytes(raw)
    parts=[]
    for index,part in enumerate(message.walk()):
        if index>100:
            raise ValueError('EMAIL_TOO_COMPLEX')
        if part.get_content_type()=='text/plain' and part.get_content_disposition()!='attachment':
            content=part.get_content()
            if not isinstance(content,str):
                raise ValueError('EMAIL_UNSUPPORTED')
            parts.append(content)
    text='\n'.join(parts)
    if not text.strip() or len(text)>16000:
        raise ValueError('EMAIL_UNSUPPORTED')
    return text


def reject_email(engine: Engine, channel_id: str, source_id: str, reason: str, policy_version: str) -> None:
    """Persist a bounded rejection and receipt, without retaining unsafe email bytes."""
    if reason not in {'EMAIL_TOO_LARGE','EMAIL_UNSUPPORTED'}:
        reason='EMAIL_UNSUPPORTED'
    try:
        with Session(engine) as session,session.begin():
            channel=session.get(SupportChannel,channel_id)
            if channel is None or not channel.active:
                raise ValueError('configured support channel unavailable')
            session.add(RejectedEmail(id=source_id,tenant_id=channel.tenant_id,reason=reason,created_at=int(time.time())))
            append_receipt(session,tenant_id=channel.tenant_id,id=str(uuid4()),timestamp=int(time.time()),allowed=False,reason=reason,rule_id='intake.imap_size_type',policy_version=policy_version,input_hash=source_id,action_digest=None,request_id=None,refund_id=None)
    except IntegrityError:
        with Session(engine) as session:
            if session.get(RejectedEmail,source_id) is None:
                raise


def ingest_email(engine: Engine,channel_id: str,source_id: str,raw: bytes,policy_version: str) -> bool:
    """Deduplicate real mailbox UIDs; rejected messages are never sent to a model."""
    with Session(engine) as session:
        if session.scalar(select(Ticket.id).where(Ticket.source_id==source_id)) or session.get(RejectedEmail,source_id):
            return False
    try:
        body=TicketInput(channel_id=channel_id,text=email_text(raw))
    except (ValueError,UnicodeError,LookupError):
        reject_email(engine,channel_id,source_id,'EMAIL_TOO_LARGE' if len(raw)>MAX_EMAIL else 'EMAIL_UNSUPPORTED',policy_version)
        return False
    try:
        with Session(engine) as session,session.begin():
            create_ticket(session,body,policy_version,source_id=source_id)
        return True
    except IntegrityError:
        # Concurrent pollers can import a UID only once.
        with Session(engine) as session:
            if session.scalar(select(Ticket.id).where(Ticket.source_id==source_id)):
                return False
        raise


def poll_once() -> int:
    """Fetch actual emails over verified TLS using BODY.PEEK (no mail writes)."""
    engine=engine_for(os.environ['DATABASE_URL'])
    version=PolicyEngine.load(Path(os.environ['POLICY_FILE'])).policy_version
    load_receipt_key()
    host,user,mailbox=os.environ['IMAP_HOST'],os.environ['IMAP_USERNAME'],os.environ['IMAP_MAILBOX']
    imported=0
    try:
        with imaplib.IMAP4_SSL(host,int(os.environ.get('IMAP_PORT','993')),ssl_context=ssl.create_default_context(),timeout=30) as client:
            client.login(user,os.environ['IMAP_PASSWORD'])
            if client.select(mailbox,readonly=True)[0]!='OK':
                raise RuntimeError('IMAP mailbox unavailable')
            _,validity=client.response('UIDVALIDITY')
            if not validity or not validity[0] or not validity[0].isdigit():
                raise RuntimeError('IMAP UIDVALIDITY required')
            status,rows=client.uid('search',None,'ALL')
            if status!='OK' or len(rows[0])>1048576:
                raise RuntimeError('IMAP search unavailable or too large')
            count=0
            for uid in rows[0].split():
                if not uid.isdigit():
                    raise RuntimeError('invalid UID')
                source=hashlib.sha256(b'\0'.join([host.encode(),user.encode(),mailbox.encode(),validity[0],uid])).hexdigest()
                with Session(engine) as session:
                    if session.scalar(select(Ticket.id).where(Ticket.source_id==source)) or session.get(RejectedEmail,source):
                        continue
                if count>=50:
                    break
                count+=1
                status,size_data=client.uid('fetch',uid,'(RFC822.SIZE)')
                size=re.search(rb'RFC822.SIZE (\d+)',b' '.join(v for v in size_data if isinstance(v,bytes)))
                if status!='OK' or size is None:
                    raise RuntimeError('IMAP size unavailable')
                if int(size.group(1))>MAX_EMAIL:
                    reject_email(engine,os.environ['IMAP_CHANNEL_ID'],source,'EMAIL_TOO_LARGE',version)
                    continue
                status,data=client.uid('fetch',uid,'(BODY.PEEK[])')
                chunks=[item[1] for item in data if isinstance(item,tuple) and isinstance(item[1],bytes)]
                if status!='OK' or len(chunks)!=1:
                    raise RuntimeError('IMAP fetch unavailable')
                imported+=ingest_email(engine,os.environ['IMAP_CHANNEL_ID'],source,chunks[0],version)
    finally:
        engine.dispose()
    return imported


def main() -> None:
    """Poll once or every 30s; failures emit fixed messages, never email bodies."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    while True:
        try:
            poll_once()
        except Exception:
            # Audit operational failure independently; no guessed tenant attribution.
            engine=engine_for(os.environ['DATABASE_URL'])
            try:
                with Session(engine) as session,session.begin():
                    append_receipt(session,id=str(uuid4()),timestamp=int(time.time()),allowed=False,reason='EMAIL_INTAKE_FAILED',rule_id='intake.imap',policy_version=PolicyEngine.load(Path(os.environ['POLICY_FILE'])).policy_version,input_hash=hashlib.sha256(b'').hexdigest(),action_digest=None,request_id=None,refund_id=None)
            finally:
                engine.dispose()
            if args.once:
                raise RuntimeError('IMAP intake failed') from None
        if args.once:
            return
        time.sleep(30)


if __name__=='__main__':
    main()
