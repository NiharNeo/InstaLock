"""Exactly sixty adversarial wire mutations of captured real actions/grants."""
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import Any
from tools.eval.contracts import Capture, Plan

KINDS=('changed_amount','changed_destination','changed_payment_id','other_tenant_payment','expired_grant','replayed_new_key','stale_after_webhook','forged_signature','alg_none','hs256_confusion','missing_grant','different_tool_grant','float_amount','duplicate_keys','unicode_lookalike','oversized_args')
EXPECTED=('ACTION_MISMATCH','INVALID_REQUEST','ACTION_MISMATCH','WRONG_TENANT','EXPIRED','GRANT_USED','STALE_RESOURCE','BAD_SIGNATURE','ALG_NOT_ALLOWED','ALG_NOT_ALLOWED','INVALID_REQUEST','ACTION_MISMATCH','INVALID_REQUEST','INVALID_REQUEST','ACTION_MISMATCH','REQUEST_TOO_LARGE')


@dataclass(frozen=True)
class Case:
    """A named probe and an exact expected code; secret wire bytes stay in memory."""
    index: int
    kind: str
    expected: str
    capture: Capture


def suite(plan: Plan) -> list[Case]:
    """Generate 60 cases: four each for first 12 categories, three for the last 4."""
    by_name={c.name:c for c in plan.captures}
    cases=[]
    stale=iter(c for c in plan.captures if c.role=='stale')
    for kind,expected in zip(KINDS,EXPECTED,strict=True):
        for _ in range(4 if KINDS.index(kind)<12 else 3):
            role={'expired_grant':'expired','replayed_new_key':'used','different_tool_grant':'different_tool'}.get(kind)
            capture=next(c for c in plan.captures if c.role==role) if role else by_name[plan.base_id]
            if kind=='stale_after_webhook':
                capture=next(stale)
            cases.append(Case(len(cases)+1,kind,expected,capture))
    # Consume short-lived historical grants before generating any fresh approvals.
    return sorted(cases,key=lambda c:0 if c.kind in {'expired_grant','replayed_new_key','stale_after_webhook','different_tool_grant'} else 1)


def _segment(value: dict[str,Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value,separators=(',',':')).encode()).rstrip(b'=').decode()


def wire(case: Case,action: dict[str,Any],token: str,*,alternate_payment: str,foreign_payment: str,foreign_tenant: str,public_key: bytes) -> bytes:
    """Mutate real captured values without inventing valid business records."""
    body={'action':json.loads(json.dumps(action)),'grant_token':token}
    args=body['action']['args']
    kind=case.kind
    if kind=='changed_amount':
        args['amount_paise']=args['amount_paise']-1 if args['amount_paise']>1 else 2
    elif kind=='changed_destination':
        args['destination']=args['destination'].upper()  # No second allowed enum exists.
    elif kind=='changed_payment_id':
        args['payment_id']=alternate_payment
    elif kind=='other_tenant_payment':
        args['payment_id']=foreign_payment
        body['action']['tenant_id']=foreign_tenant
    elif kind=='forged_signature':
        pieces=token.split('.')
        signature=bytearray(base64.urlsafe_b64decode(pieces[2]+'='*(-len(pieces[2])%4)))
        signature[0]^=1
        pieces[2]=base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        body['grant_token']='.'.join(pieces)
    elif kind in {'alg_none','hs256_confusion'}:
        pieces=token.split('.')
        header=json.loads(base64.urlsafe_b64decode(pieces[0]+'='*(-len(pieces[0])%4)))
        header['alg']='none' if kind=='alg_none' else 'HS256'
        unsigned=_segment(header)+'.'+pieces[1]
        body['grant_token']=unsigned+'.'+('' if kind=='alg_none' else base64.urlsafe_b64encode(hmac.new(public_key,unsigned.encode(),hashlib.sha256).digest()).rstrip(b'=').decode())
    elif kind=='missing_grant':
        del body['grant_token']
    elif kind=='unicode_lookalike':
        # The real Razorpay prefix contains ASCII a; Cyrillic а is NFC but distinct.
        args['payment_id']=args['payment_id'].replace('a','\u0430',1)
    elif kind=='oversized_args':
        args['payment_id']=args['payment_id']*max(1,70000//len(args['payment_id'])+1)
    raw=json.dumps(body,separators=(',',':'),ensure_ascii=False).encode()
    amount=action['args']['amount_paise']
    if kind=='float_amount':
        raw=raw.replace(('"amount_paise":'+str(amount)).encode(),('"amount_paise":'+str(amount)+'.0').encode(),1)
    elif kind=='duplicate_keys':
        raw=raw.replace(('"amount_paise":'+str(amount)).encode(),('"amount_paise":'+str(amount)+',"amount_paise":'+str(amount)).encode(),1)
    return raw
