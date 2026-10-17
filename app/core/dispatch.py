"""Durable encrypted handoff of human-issued grants to the trusted executor."""
import os
import stat
import time
from uuid import uuid4
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session
from typing import Any
from intentlock.db import ApprovalDispatch, Proposal


def load_dispatch_cipher() -> Fernet:
    """Read the dedicated dispatch encryption key from a protected local secret file."""
    path=os.environ['DISPATCH_KEY_FILE']
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('protected dispatch key required')
        raw=stream.read(129).strip()
    if len(raw)!=44:
        raise ValueError('invalid dispatch key')
    return Fernet(raw)


def dispatch_pending(gateway: Any) -> None:
    """Lease queued handoffs; retries use one immutable action, token and operation key.

    No grant is minted here. Executor verification remains mandatory. A crash after
    provider dispatch is recovered by the executor's existing operation reconciler.
    """
    cipher=load_dispatch_cipher()
    if gateway.executor is None:
        return
    now=int(time.time())
    with Session(gateway.engine) as session:
        identifiers=list(session.scalars(select(ApprovalDispatch.proposal_id).where(ApprovalDispatch.status=='QUEUED',ApprovalDispatch.next_attempt_at<=now,or_(ApprovalDispatch.lease_until.is_(None),ApprovalDispatch.lease_until<=now)).order_by(ApprovalDispatch.created_at).limit(20)))
    for identifier in identifiers:
        now=int(time.time())
        owner=str(uuid4())
        with Session(gateway.engine) as session,session.begin():
            changed=session.execute(update(ApprovalDispatch).where(ApprovalDispatch.proposal_id==identifier,ApprovalDispatch.status=='QUEUED',ApprovalDispatch.next_attempt_at<=now,or_(ApprovalDispatch.lease_until.is_(None),ApprovalDispatch.lease_until<=now)).values(lease_owner=owner,lease_until=now+60))
            if changed.rowcount!=1:
                continue
            job=session.get(ApprovalDispatch,identifier)
            proposal=session.get(Proposal,identifier)
            if job is None or proposal is None or proposal.tenant_id!=job.tenant_id:
                raise ValueError('dispatch proposal binding missing')
            tenant=job.tenant_id
            try:
                token=cipher.decrypt(job.token_ciphertext.encode()).decode()
            except (InvalidToken,UnicodeError):
                session.execute(update(ApprovalDispatch).where(ApprovalDispatch.proposal_id==identifier,ApprovalDispatch.lease_owner==owner).values(lease_owner=None,lease_until=None,next_attempt_at=now+60,reason='DISPATCH_DECRYPT_FAILED'))
                session.info['receipt_tenant']=tenant
                gateway.audit(session,b'','DISPATCH_DECRYPT_FAILED','dispatch.encryption',False,request_id=identifier)
                continue
            body={'action':proposal.action,'grant_token':token,'idempotency_key':job.idempotency_key,'service_id':proposal.service_id}
        try:
            result=gateway.executor.call('internal/execute',body)
            # Only authenticated executor results with stable state are terminal handoffs.
            state=result.get('status')
            accepted=state in {'PENDING','DONE','FAILED'} and type(result.get('operation_id')) is str
            retry=result.get('reason') in {'AUDIT_UNAVAILABLE','INTERNAL_ERROR','EXECUTOR_UNAVAILABLE','PROVIDER_UNCERTAIN'}
            if not accepted and (retry or result.get('_http_status',500)>=500):
                raise ValueError('executor handoff unavailable')
            reason=str(result.get('reason','DISPATCH_DENIED'))
            with Session(gateway.engine) as session,session.begin():
                changed=session.execute(update(ApprovalDispatch).where(ApprovalDispatch.proposal_id==identifier,ApprovalDispatch.lease_owner==owner).values(status='DELIVERED' if accepted else 'FAILED',reason=reason,operation_id=result.get('operation_id') if accepted else None,token_ciphertext='',lease_owner=None,lease_until=None))
                if changed.rowcount==1:
                    session.info['receipt_tenant']=tenant
                    gateway.audit(session,b'', 'DISPATCH_DELIVERED' if accepted else 'DISPATCH_DENIED','dispatch.handoff',accepted,request_id=identifier)
        except Exception:
            # Retain encrypted token after network loss: executor idempotency resolves retries.
            with Session(gateway.engine) as session,session.begin():
                changed=session.execute(update(ApprovalDispatch).where(ApprovalDispatch.proposal_id==identifier,ApprovalDispatch.lease_owner==owner).values(lease_owner=None,lease_until=None,next_attempt_at=int(time.time())+10,reason='DISPATCH_RETRY'))
                if changed.rowcount==1:
                    session.info['receipt_tenant']=tenant
                    gateway.audit(session,b'','DISPATCH_RETRY','dispatch.handoff',False,request_id=identifier)


def main() -> None:
    """Generate a new dedicated encrypted-handoff key without overwriting existing keys."""
    import argparse
    from pathlib import Path
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(Fernet.generate_key())
    print('Dispatch encryption key generated in protected local file.')


if __name__=='__main__':
    main()
