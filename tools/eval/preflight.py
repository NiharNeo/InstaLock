"""Read-only live readiness census; records missing prerequisites, never runs refund cases."""
import os
import time
from uuid import uuid4
from typing import Any
import httpx
from sqlalchemy import func,select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from intentlock.db import EvalRun,Operation,Order,Payment,Proposal,Ticket,WebhookEvent


def readiness_census(engine: Engine,tenant: str,gateway_url: str) -> dict[str,Any]:
    """Observe actual tenant records and gateway health without approving or executing anything."""
    with Session(engine) as session:
        payments=list(session.execute(select(Payment.id,Order.paid_paise,Order.refunded_paise).join(Order,Order.id==Payment.order_id).where(Payment.tenant_id==tenant,Order.tenant_id==tenant)))
        counts={name:session.scalar(select(func.count()).select_from(model).where(model.tenant_id==tenant)) for name,model in [('tickets',Ticket),('proposals',Proposal),('webhook_events',WebhookEvent)]}
        tenant_count=session.scalar(select(func.count(func.distinct(Payment.tenant_id))))
        pending=session.scalar(select(func.count()).select_from(Operation).where(Operation.tenant_id==tenant,Operation.status=='PENDING'))
    try:
        with httpx.Client(timeout=10,follow_redirects=False) as client:
            response=client.get(gateway_url.rstrip('/')+'/health/ready')
            gateway_ready=response.status_code==200 and response.json().get('status')=='ready'
    except Exception:
        gateway_ready=False
    missing=[]
    if not gateway_ready:missing.append('GATEWAY_NOT_READY')
    if not counts['tickets']:missing.append('REAL_TICKETS_REQUIRED')
    if not any(row.paid_paise>row.refunded_paise for row in payments):missing.append('REFUNDABLE_PAYMENT_REQUIRED')
    if tenant_count<2:missing.append('OTHER_TENANT_PAYMENT_AND_EXECUTOR_REQUIRED')
    if not counts['webhook_events']:missing.append('VERIFIED_WEBHOOK_HISTORY_REQUIRED')
    if pending:missing.append('PENDING_OPERATIONS_MUST_SETTLE')
    # No plan was supplied or validated by this technical census. Full Runner.preflight
    # must verify actual protected tokens, four distinct stale grants and capacity.
    missing.append('VALIDATED_CAPTURE_PLAN_REQUIRED')
    return {'kind':'READINESS','suite_executed':False,'gateway_ready':gateway_ready,'observed':{**counts,'mapped_payments':len(payments),'mapped_tenants':tenant_count,'pending_operations':pending,'remaining_refundable_paise':sum(row.paid_paise-row.refunded_paise for row in payments)},'missing_prerequisites':missing,'stop_reason':'LIVE_EVAL_PREREQUISITES_MISSING','misuse_expected':60,'valid_expected':40,'misuse_attempted':0,'valid_attempted':0,'baseline':'NOT_RUN'}


def record_preflight(engine: Engine,tenant: str,gateway_url: str,git_sha: str | None) -> str:
    """Persist a real BLOCKED readiness run, with zero attempted or invented suite results."""
    identifier=str(uuid4());started=int(time.time())
    summary=readiness_census(engine,tenant,gateway_url)
    with Session(engine) as session,session.begin():
        session.add(EvalRun(id=identifier,tenant_id=tenant,git_sha=git_sha,started_at=started,finished_at=int(time.time()),status='BLOCKED',summary=summary,cases=[]))
    return identifier


def main() -> None:
    """Run technical readiness against the actual mounted stack ledger and live gateway."""
    from tools.eval.runner import git_sha
    from pathlib import Path
    from intentlock.db import engine_for
    engine=engine_for(os.environ['DATABASE_URL'])
    try:
        identifier=record_preflight(engine,os.environ['EVAL_TENANT_ID'],os.environ['EVAL_GATEWAY_URL'],git_sha(Path.cwd()))
        with Session(engine) as session:
            row=session.get(EvalRun,identifier)
            print('Readiness run:',row.id,'Status:',row.status)
            for reason in row.summary['missing_prerequisites']:print('-',reason)
            print('Financial suite cases executed: 0; approvals issued: 0; provider refunds attempted: 0.')
    finally:engine.dispose()


if __name__=='__main__':
    main()
