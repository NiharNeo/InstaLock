"""CLI for real capture export and live evaluation; no fixture or stub runtime mode."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
from uuid import uuid4
from sqlalchemy.orm import Session
from app.core.canonical import _load_json
from intentlock.db import EvalRun, Proposal, engine_for
from tools.eval.captures import read_secret, validate_capture, write_secret
from tools.eval.contracts import Capture, Plan
from tools.eval.observer import Observer
from tools.eval.runner import EvaluationStopped, Runner, git_sha, percentiles


def summary_table(row: EvalRun) -> str:
    """Print slide-ready observed counts, never infer numbers for unexecuted cases."""
    summary=row.summary
    timing=summary.get('gateway_path_overhead_valid',{})
    def shown(value):
        return 'not measured' if value is None else str(value)
    rows=[('Run',row.id),('Status',row.status),('Git SHA',row.git_sha or 'unavailable'),('Misuse exact-code + zero-refund passes',f"{summary.get('misuse_passed',0)} / {summary.get('misuse_attempted',0)} attempted (60 required)"),('Valid completed',f"{summary.get('valid_completed',0)} / {summary.get('valid_attempted',0)} attempted (40 required)"),('Concurrency exactly one DB + provider refund',shown(summary.get('concurrency_passed'))),('Baseline actual provider refunds',shown(summary.get('baseline_actual_provider_refunds'))),('Baseline actual POSTs / unrepresentable',f"{summary.get('baseline_provider_posts',0)} / {summary.get('baseline_not_representable',0)}"),('Valid latency samples',shown(timing.get('samples'))),('Overhead p50 / p95 / p99 ms',' / '.join(shown(timing.get(k)) for k in ('p50_ms','p95_ms','p99_ms'))),('Stop reason',summary.get('stop_reason','none'))]
    return '\n'.join(['| Measurement | Observed result |','| --- | --- |',*[f'| {key} | {value} |' for key,value in rows]])


def run_command(args: argparse.Namespace) -> int:
    """Persist even blocked/failed configured runs; never print secrets in exceptions."""
    engine=engine_for(os.environ['DATABASE_URL'])
    tenant=os.environ['EVAL_TENANT_ID']
    identifier=str(uuid4())
    sha=git_sha(Path.cwd())
    with Session(engine) as session,session.begin():
        session.add(EvalRun(id=identifier,tenant_id=tenant,git_sha=sha,started_at=int(time.time()),finished_at=None,status='RUNNING',summary={'misuse_expected':60,'valid_expected':40,'baseline':'NOT_RUN'},cases=[]))
    runner=None
    try:
        if sha is None:
            raise EvaluationStopped('GIT_SHA_UNAVAILABLE')
        commands=_load_json(os.environ['EVAL_PROVIDER_COMMANDS'])
        observer=Observer(engine,commands)
        runner=Runner(engine,tenant,os.environ['EVAL_GATEWAY_URL'],os.environ['EVAL_AGENT_SERVICE_KEY'],os.environ['EVAL_OPERATOR_SESSION'],os.environ['EVAL_CSRF_TOKEN'],os.environ['EVAL_APP_ORIGIN'],observer,timeout=args.settle_timeout,observe_seconds=args.observe_seconds)
        runner.run_id=identifier
        runner.started=True
        raw_plan=read_secret(args.plan)
        import hashlib
        runner.summary['capture_plan_hash']=hashlib.sha256(raw_plan).hexdigest()
        plan=Plan.model_validate(_load_json(raw_plan))
        state=runner.run(plan,baseline_budget=args.baseline_max_paise if args.baseline else None)
    except KeyboardInterrupt:
        state='INCONCLUSIVE'
        with Session(engine) as session,session.begin():
            row=session.get(EvalRun,identifier)
            row.summary={**row.summary,'stop_reason':'INTERRUPTED_EXTERNAL_EFFECTS_MAY_STILL_SETTLE'}
            row.status=state
            row.finished_at=int(time.time())
    except Exception as error:
        reason=str(error) if isinstance(error,(EvaluationStopped,ValueError)) and re.fullmatch(r'[A-Z0-9_]{1,100}',str(error)) else 'EVAL_PRECONDITION_OR_TRANSPORT_UNAVAILABLE'
        with Session(engine) as session,session.begin():
            row=session.get(EvalRun,identifier)
            failed=any(result.get('passed') is False for result in row.cases)
            state='FAIL' if failed else 'INCONCLUSIVE' if row.cases else 'BLOCKED'
            row.status=state
            row.finished_at=int(time.time())
            row.summary={**row.summary,'stop_reason':reason}
    finally:
        if runner:
            runner.close()
    with Session(engine) as session:
        row=session.get(EvalRun,identifier)
        print(summary_table(row))
    engine.dispose()
    return 0 if state=='PASS' else 1 if state=='FAIL' else 2


def main() -> None:
    """Export real captures or run real tests; configuration schema contains no data."""
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    schema=commands.add_parser('schema')
    schema.add_argument('--capture',action='store_true')
    capture=commands.add_parser('capture')
    capture.add_argument('--name',required=True)
    capture.add_argument('--role',required=True,choices=['fresh','expired','used','stale','different_tool'])
    capture.add_argument('--ticket-id',required=True)
    capture.add_argument('--proposal-id',required=True)
    capture.add_argument('--grant-file',type=Path,required=True)
    capture.add_argument('--webhook-event-id')
    capture.add_argument('--other-tool-action-file',type=Path)
    capture.add_argument('--output',type=Path,required=True)
    plan=commands.add_parser('plan')
    plan.add_argument('--capture-file',type=Path,action='append',required=True)
    plan.add_argument('--base-name',required=True)
    plan.add_argument('--alternate-name',required=True)
    plan.add_argument('--foreign-payment-id',required=True)
    plan.add_argument('--valid-name',action='append',required=True)
    plan.add_argument('--concurrency-name',required=True)
    plan.add_argument('--output',type=Path,required=True)
    run=commands.add_parser('run')
    run.add_argument('--plan',type=Path,required=True)
    run.add_argument('--baseline',action='store_true')
    run.add_argument('--baseline-max-paise',type=int)
    run.add_argument('--settle-timeout',type=int,default=180)
    run.add_argument('--observe-seconds',type=int,default=5)
    args=parser.parse_args()
    if args.command=='schema':
        print(json.dumps((Capture if args.capture else Plan).model_json_schema(),indent=2))
        return
    if args.command=='plan':
        try:
            captures=[Capture.model_validate(_load_json(read_secret(path))) for path in args.capture_file]
            schedule=[args.valid_name[index%len(args.valid_name)] for index in range(40)]
            plan=Plan(captures=captures,base_id=args.base_name,alternate_id=args.alternate_name,foreign_payment_id=args.foreign_payment_id,valid_ids=schedule,concurrency_id=args.concurrency_name)
            write_secret(args.output,plan.model_dump(mode='json'))
        except Exception:
            print('PLAN_VALIDATION_FAILED: protected real captures and 40 valid slots required.',file=sys.stderr)
            sys.exit(2)
        print('Protected plan created from actual capture artifacts; no business data generated.')
        return
    if args.command=='run':
        if args.baseline and (args.baseline_max_paise is None or not 0<args.baseline_max_paise<=9007199254740991):
            parser.error('--baseline requires an explicit positive safe integer --baseline-max-paise')
        sys.exit(run_command(args))
    engine=engine_for(os.environ['DATABASE_URL'])
    try:
        with Session(engine) as session:
            row=session.get(Proposal,args.proposal_id)
            if row is None:
                raise ValueError('ACTUAL_PROPOSAL_REQUIRED')
            record=Capture(name=args.name,role=args.role,ticket_id=args.ticket_id,proposal_id=row.id,action=row.action,grant_token=read_secret(args.grant_file).decode().strip(),webhook_event_id=args.webhook_event_id,other_tool_action=_load_json(read_secret(args.other_tool_action_file)) if args.other_tool_action_file else None)
            validate_capture(session,record,row.tenant_id)
        write_secret(args.output,record.model_dump(mode='json'))
        print('Captured real ticket/proposal/grant; secret output created with mode 0600.')
    except Exception:
        print('CAPTURE_VALIDATION_FAILED: no secret artifact was exported.',file=sys.stderr)
        sys.exit(2)
    finally:
        engine.dispose()


if __name__=='__main__':
    main()
