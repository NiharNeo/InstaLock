"""Trusted executor-local test-mode observer/baseline CLI. Never exposed over HTTP."""
import argparse
import json
import re
import sys
from typing import Any
from app.executor.config import ExecutorSettings
from app.executor.razorpay import RazorpayTestAdapter
from app.executor.models import ProviderRejected, ProviderUncertain
from intentlock.schema import parse_json


def probe(settings: ExecutorSettings, adapter: RazorpayTestAdapter, data: dict[str,Any], *, bypass: bool) -> dict[str,Any]:
    """Observe actual test-account payments/refunds, or explicitly bypass the gateway."""
    if data.get('tenant_id')!=settings.tenant_id:
        raise ValueError('probe tenant mismatch')
    if data.get('op')=='snapshot':
        identifiers=data['payment_ids']
        if not isinstance(identifiers,list) or not 1<=len(identifiers)<=200 or any(not isinstance(p,str) or not re.fullmatch(r'pay_[A-Za-z0-9]{1,124}',p) for p in identifiers):
            raise ValueError('invalid payment list')
        return {'mode':'razorpay-test','tenant_id':settings.tenant_id,'payments':{identifier:{'payment':adapter.get_payment(identifier).model_dump(mode='json'),'refunds':[r.model_dump(mode='json') for r in adapter.list_refunds(identifier)]} for identifier in identifiers}}
    if data.get('op')!='baseline' or not bypass:
        raise ValueError('baseline requires executor-local --bypass flag')
    try:
        body=parse_json(data['wire'].encode())
        args=body['action']['args']
        payment_id=args['payment_id']
        if not isinstance(payment_id,str) or not re.fullmatch(r'pay_[A-Za-z0-9]{1,124}',payment_id):
            return {'outcome':'NOT_REPRESENTABLE','reason':'INVALID_PROVIDER_PAYMENT_ID'}
        reference=data['reference']
        if not re.fullmatch(r'[A-Za-z0-9_-]{10,64}',reference):
            raise ValueError('bad provider idempotency reference')
    except (ValueError,KeyError,TypeError):
        return {'outcome':'NOT_REPRESENTABLE','reason':'INVALID_WIRE_REQUEST'}
    try:
        # Intentionally unsafe baseline projection: no grant/policy checks. This
        # CLI stays inside the trusted executor, with its test-only credentials.
        response=adapter._request('POST','payments/'+payment_id+'/refund',body={'amount':args.get('amount_paise'),'speed':'normal','receipt':reference},reference=reference)
        return {'outcome':'PROVIDER_ACCEPTED','refund':adapter._refund(response).model_dump(mode='json'),'projection':'payment_id,amount_paise; authorization fields discarded'}
    except ProviderRejected:
        return {'outcome':'PROVIDER_REJECTED'}
    except ProviderUncertain:
        return {'outcome':'PROVIDER_UNCERTAIN'}


def main() -> None:
    """Read bounded JSON on stdin; write evidence only, never environment secrets."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bypass',action='store_true')
    args=parser.parse_args()
    raw=sys.stdin.buffer.read(262145)
    if len(raw)>262144:
        raise ValueError('probe input too large')
    settings=ExecutorSettings.from_env()
    adapter=RazorpayTestAdapter(settings)
    try:
        result=probe(settings,adapter,parse_json(raw),bypass=args.bypass)
        encoded=json.dumps(result,separators=(',',':'))
        if len(encoded.encode())>4194304:
            raise ValueError('probe output too large')
        print(encoded)
    finally:
        adapter.close()


if __name__=='__main__':
    main()
