"""Independent live provider evidence via the trusted executor's local CLI."""
import json
import subprocess
from typing import Any
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from intentlock.db import Payment, Refund


class Observer:
    """Route actual merchant accounts to executor processes without reading their keys."""
    def __init__(self,engine: Engine,commands: dict[str,list[str]]):
        """Accept explicit deployment-owned argv vectors, never a shell command."""
        if not commands or any(not tenant or not isinstance(argv,list) or not argv or any(type(s) is not str or not s for s in argv) for tenant,argv in commands.items()):
            raise ValueError('PROVIDER_COMMANDS_REQUIRED')
        self.engine,self.commands=engine,commands

    def call(self,tenant: str,data: dict[str,Any],*,bypass: bool = False) -> dict[str,Any]:
        """Read bounded evidence from a real executor subprocess with no fallback."""
        if tenant not in self.commands:
            raise ValueError('PROVIDER_OBSERVER_UNAVAILABLE')
        command=[*self.commands[tenant],*(['--bypass'] if bypass else [])]
        result=subprocess.run(command,input=json.dumps({**data,'tenant_id':tenant}).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
        if result.returncode or len(result.stdout)>4194304:
            raise ValueError('PROVIDER_PROBE_FAILED')
        try:
            payload=json.loads(result.stdout)
        except Exception:
            raise ValueError('PROVIDER_PROBE_INVALID') from None
        if type(payload) is not dict:
            raise ValueError('PROVIDER_PROBE_INVALID')
        return payload

    def snapshot(self,payment_ids: list[str]) -> dict[str,Any]:
        """Query both SQL ledger and actual provider collections for each real payment."""
        groups: dict[str,list[str]]={}
        with Session(self.engine) as session:
            identifiers=sorted(set(payment_ids))
            payments=list(session.execute(select(Payment.id,Payment.tenant_id).where(Payment.id.in_(identifiers))))
            if {row.id for row in payments}!=set(identifiers):
                raise ValueError('OBSERVED_PAYMENT_NOT_IN_DATABASE')
            for payment in sorted(payments,key=lambda row: row.id):
                groups.setdefault(payment.tenant_id,[]).append(payment.id)
            db_ids=list(session.scalars(select(Refund.id).join(Payment,Refund.order_id==Payment.order_id).where(Payment.id.in_(payment_ids))))
        payments={}
        for tenant,identifiers in groups.items():
            evidence=self.call(tenant,{'op':'snapshot','payment_ids':identifiers})
            if evidence.get('mode')!='razorpay-test' or evidence.get('tenant_id')!=tenant or set(evidence.get('payments',{}))!=set(identifiers):
                raise ValueError('TEST_PROVIDER_EVIDENCE_REQUIRED')
            payments.update(evidence['payments'])
        return {'db_ids':sorted(db_ids),'payments':payments}


def delta(before: dict[str,Any],after: dict[str,Any]) -> dict[str,Any]:
    """Compare immutable refund IDs and absolute provider balances; never infer success."""
    if set(before['payments'])!=set(after['payments']):
        raise ValueError('INCONSISTENT_OBSERVATION')
    created=[]
    balances={}
    for identifier,previous in before['payments'].items():
        current=after['payments'][identifier]
        old={row['provider_id'] for row in previous['refunds']}
        created.extend(row for row in current['refunds'] if row['provider_id'] not in old)
        balances[identifier]=current['payment']['amount_refunded_paise']-previous['payment']['amount_refunded_paise']
    return {'db_refund_ids':sorted(set(after['db_ids'])-set(before['db_ids'])),'provider_refunds':created,'balance_delta_paise':balances}
