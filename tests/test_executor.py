"""Synthetic business/provider fixtures exist exclusively in this test module."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import hmac
import json
import threading
import time
from typing import Any
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from test_gateway_v1 import fixture_gateway, authorized
from test_policy import fixture_policy_document, fixture_v1_action
from app.core.canonical import parse_action
from app.core.policy import PolicyEngine
from app.executor.config import ExecutorSettings
from app.executor.main import create_app
from app.executor.models import ProviderPayment, ProviderRefund, ProviderUncertain
from app.executor.razorpay import RazorpayTestAdapter
from app.executor.resources import apply_payment
from app.executor.service import ExecutorService
from intentlock.db import Operation, Payment, Proposal, Resource, UsedGrant


class FixtureProvider:
    """Thread-safe fixture provider implementing the documented idempotency contract."""
    def __init__(self):
        self.payment=ProviderPayment(provider_id='pay_fixture1',amount_paise=100000,amount_refunded_paise=0,currency='INR',status='captured')
        self.refunds={}
        self.calls=0
        self.lock=threading.Lock()
        self.lose_response=False

    def get_payment(self,payment_id):
        with self.lock:
            return self.payment

    def create_refund(self,payment_id,amount_paise,idempotency_ref):
        with self.lock:
            self.calls+=1
            if idempotency_ref not in self.refunds:
                self.refunds[idempotency_ref]=ProviderRefund(provider_id='rfnd_fixture1',payment_id=payment_id,amount_paise=amount_paise,currency='INR',status='processed',receipt=idempotency_ref)
                self.payment=self.payment.model_copy(update={'amount_refunded_paise':self.payment.amount_refunded_paise+amount_paise})
            if self.lose_response:
                self.lose_response=False
                raise ProviderUncertain('fixture response lost after acceptance')
            return self.refunds[idempotency_ref]

    def find_refund(self,payment_id,idempotency_ref):
        with self.lock:
            return self.refunds.get(idempotency_ref)


@pytest.fixture
def fixture_executor(fixture_gateway: Any):
    c=fixture_gateway
    provider=FixtureProvider()
    with Session(c['engine']) as session,session.begin():
        session.delete(session.get(Payment,'payment'))
        session.flush()
        session.add(Payment(id='pay_fixture1',tenant_id='tenant-a',order_id='order',destination_kind='original_payment',in_flight=False))
    c['action']['args']['payment_id']='pay_fixture1'
    # Use actual provider projection for human preview/approval, with fixture I/O only.
    class FixtureAdapter:
        def fetch(self,session,payment_id,tenant_id,*,for_update=False):
            return apply_payment(session,provider.get_payment(payment_id),tenant_id)
    c['app'].state.gateway.adapter=FixtureAdapter()
    settings=ExecutorSettings(c['config'].database_url,c['policy_path'],'fixture-issuer','tenant-a','acc_fixture','rzp_test_fixture','fixture-secret','w'*32,'i'*32)
    service=ExecutorService(c['engine'],settings,PolicyEngine.load(c['policy_path']),provider)
    proposal,token=authorized(c)
    return c,provider,service,parse_action(c['action']),token


def test_fifty_execute_calls_one_refund(fixture_executor):
    c,p,s,a,t=fixture_executor
    with ThreadPoolExecutor(max_workers=50) as pool:
        results=list(pool.map(lambda n:s.execute(a,t,'fixture-key-'+str(n),'fixture-service'),range(50)))
    assert sum(r['reason']=='EXECUTED' for r in results)==1,results
    assert p.calls==len(p.refunds)==1
    assert all(r['reason'] in {'EXECUTED','GRANT_USED'} for r in results)


def test_crash_after_reservation_recovers(fixture_executor):
    c,p,s,a,t=fixture_executor
    reservation=s.reserve(a,t,'fixture-recovery','fixture-service')
    assert p.calls==0
    with Session(s.engine) as session,session.begin():
        session.execute(update(Operation).values(created_at=int(time.time())-61))
    assert s.reconcile()[0]['reason']=='EXECUTED'
    assert s.reconcile()==[]
    assert p.calls==1
    assert s.execute(a,t,'fixture-recovery','fixture-service')['reason']=='EXECUTED'
    assert s.execute(a,t,'fixture-new','fixture-service')['reason']=='GRANT_USED'


def test_lost_provider_response_is_reconciled_without_second_post(fixture_executor):
    c,p,s,a,t=fixture_executor
    p.lose_response=True
    result=s.execute(a,t,'fixture-lost','fixture-service')
    assert result['status']=='PENDING'
    with Session(s.engine) as session:
        assert session.get(Payment,a.args.payment_id).in_flight
    assert s.run(result['operation_id'],reconcile=True)['status']=='DONE'
    assert p.calls==1


def test_stale_resource_burns_grant_without_provider_call(fixture_executor):
    c,p,s,a,t=fixture_executor
    p.payment=p.payment.model_copy(update={'amount_refunded_paise':1})
    result=s.execute(a,t,'fixture-stale','fixture-service')
    assert result['reason']=='STALE_RESOURCE',result
    assert p.calls==0
    with Session(s.engine) as session:
        assert not session.get(Payment,a.args.payment_id).in_flight
        assert session.scalar(select(UsedGrant.status))=='USED'


def test_idempotency_conflict(fixture_executor):
    c,p,s,a,t=fixture_executor
    assert s.execute(a,t,'fixture-same','fixture-service')['allowed']
    changed=parse_action({**a.model_dump(mode='json'),'args':{**a.args.model_dump(mode='json'),'amount_paise':1}})
    assert s.execute(changed,t,'fixture-same','fixture-service')['reason']=='IDEMPOTENCY_CONFLICT'
    assert p.calls==1


def test_webhook_signature_dedup_and_absolute_state(fixture_executor):
    c,p,s,a,t=fixture_executor
    body=json.dumps({'account_id':'acc_fixture','event':'refund.processed','payload':{'refund':{'entity':{'payment_id':'pay_fixture1'}}}}).encode()
    signature=hmac.new(s.settings.webhook_secret.encode(),body,hashlib.sha256).hexdigest()
    with TestClient(create_app(s.settings,provider=p)) as client:
        assert client.post('/v1/webhooks/razorpay',content=body).json()['reason']=='BAD_SIGNATURE'
        p.payment=p.payment.model_copy(update={'amount_refunded_paise':100})
        headers={'Content-Type':'application/json','X-Razorpay-Signature':signature,'x-razorpay-event-id':'fixture-event'}
        assert client.post('/v1/webhooks/razorpay',content=body,headers=headers).json()['reason']=='WEBHOOK_APPLIED'
        assert client.post('/v1/webhooks/razorpay',content=body,headers=headers).json()['reason']=='WEBHOOK_DUPLICATE'
        with Session(s.engine) as session:
            assert session.get(Resource,a.args.payment_id).amount_refunded_paise==100
        assert client.post('/internal/execute',json={}).status_code==401


def test_adapter_uses_real_protocol_and_identical_idempotency(fixture_executor):
    c,p,s,a,t=fixture_executor
    requests=[]
    def transport(request):
        requests.append(request)
        return httpx.Response(200,json={'id':'rfnd_fixture1','payment_id':'pay_fixture1','amount':499,'currency':'INR','status':'processed','receipt':'fixture-reference'})
    adapter=RazorpayTestAdapter(s.settings,transport=httpx.MockTransport(transport))
    try:
        for _ in range(2):
            assert adapter.create_refund('pay_fixture1',499,'fixture-reference').amount_paise==499
        assert requests[0].content==requests[1].content
        assert requests[0].headers['X-Refund-Idempotency']=='fixture-reference'
        assert requests[0].url=='https://api.razorpay.com/v1/payments/pay_fixture1/refund'
        with pytest.raises(ValueError):
            adapter.create_refund('pay_fixture1',499.0,'fixture-reference')
    finally:
        adapter.close()
    with pytest.raises(ValueError):
        replace(s.settings,key_id='rzp_live_fixture')


def test_gateway_remote_preview_approval_and_execute(fixture_executor):
    from app.executor.client import ExecutorClient
    from test_gateway_v1 import execute
    c,p,s,a,t=fixture_executor
    with TestClient(create_app(s.settings,provider=p)) as executor_http:
        def transport(request):
            response=executor_http.request(request.method,request.url.path,content=request.content,headers=dict(request.headers))
            return httpx.Response(response.status_code,content=response.content,headers=dict(response.headers))
        remote=ExecutorClient('http://executor:8001',s.settings.internal_token)
        remote.client.close()
        remote.client=httpx.Client(base_url='http://executor:8001/',headers={'Authorization':'Bearer '+s.settings.internal_token},transport=httpx.MockTransport(transport))
        c['app'].state.gateway.adapter=remote
        c['app'].state.gateway.executor=remote
        try:
            _,token=authorized(c)
            result=execute(c,token)
            assert result.status_code==200,result.text
            assert result.json()['reason']=='EXECUTED',result.text
            assert p.calls==1
        finally:
            remote.client.close()


def test_same_key_fifty_calls_and_expired_grant(fixture_executor):
    c,p,s,a,t=fixture_executor
    with ThreadPoolExecutor(max_workers=50) as pool:
        results=list(pool.map(lambda _:s.execute(a,t,'fixture-shared','fixture-service'),range(50)))
    assert p.calls==1
    assert all(r.get('status') in {'PENDING','DONE'} for r in results),results
    assert s.execute(a,t,'fixture-shared','fixture-service')['status']=='DONE'


def test_expired_database_cas_denies_before_dispatch(fixture_executor):
    c,p,s,a,t=fixture_executor
    with Session(s.engine) as session,session.begin():
        session.execute(update(UsedGrant).values(expires_at=int(time.time())))
    assert s.execute(a,t,'fixture-expired','fixture-service')['reason']=='EXPIRED'
    assert p.calls==0


def test_bad_signature_rolls_back_grant_consumption(fixture_executor):
    c,p,s,a,t=fixture_executor
    parts=t.split('.')
    parts[2]=('A' if parts[2][0]!='A' else 'B')+parts[2][1:]
    assert s.execute(a,'.'.join(parts),'fixture-forged','fixture-service')['reason']=='BAD_SIGNATURE'
    with Session(s.engine) as session:
        assert session.scalar(select(UsedGrant.status))=='ACTIVE'
    assert p.calls==0


def test_provider_failure_stays_pending_and_stale_worker_cannot_overwrite(fixture_executor):
    c,p,s,a,t=fixture_executor
    reservation=s.reserve(a,t,'fixture-lease','fixture-service')
    owner,_=s._claim(reservation.operation_id)
    assert owner
    with Session(s.engine) as session,session.begin():
        session.execute(update(Operation).values(lease_until=0))
    assert s.run(reservation.operation_id,reconcile=True)['status']=='DONE'
    assert s._pending(reservation.operation_id,owner,'PROVIDER_UNCERTAIN')['status']=='DONE'
    assert p.calls==1


def test_adapter_rejects_uncertain_http_and_scans_real_refund_pages(fixture_executor):
    c,p,s,a,t=fixture_executor
    calls=[]
    def transport(request):
        calls.append(request)
        if request.method=='POST':
            return httpx.Response(409,json={'error':{'description':'fixture conflict'}})
        return httpx.Response(200,json={'count':1,'items':[{'id':'rfnd_fixture1','payment_id':'pay_fixture1','amount':499,'currency':'INR','status':'processed','receipt':'fixture-reference'}]})
    adapter=RazorpayTestAdapter(s.settings,transport=httpx.MockTransport(transport))
    try:
        assert adapter.find_refund('pay_fixture1','fixture-reference').provider_id=='rfnd_fixture1'
        with pytest.raises(ProviderUncertain):
            adapter.create_refund('pay_fixture1',499,'fixture-reference')
        assert len(calls)==2
    finally:
        adapter.close()


def test_webhook_tamper_account_binding_and_reordered_events(fixture_executor):
    c,p,s,a,t=fixture_executor
    def signed(body,event_id):
        raw=json.dumps(body).encode()
        return raw,{'Content-Type':'application/json','X-Razorpay-Signature':hmac.new(s.settings.webhook_secret.encode(),raw,hashlib.sha256).hexdigest(),'x-razorpay-event-id':event_id}
    data={'account_id':'acc_fixture','event':'payment.captured','payload':{'payment':{'entity':{'id':'pay_fixture1','amount_refunded':0}}}}
    with TestClient(create_app(s.settings,provider=p)) as client:
        raw,headers=signed(data,'fixture-first')
        assert client.post('/v1/webhooks/razorpay',content=raw+b' ',headers=headers).json()['reason']=='BAD_SIGNATURE'
        wrong={**data,'account_id':'acc_other'}
        raw,headers=signed(wrong,'fixture-wrong')
        assert client.post('/v1/webhooks/razorpay',content=raw,headers=headers).json()['reason']=='WEBHOOK_SCOPE_MISMATCH'
        p.payment=p.payment.model_copy(update={'amount_refunded_paise':1000})
        raw,headers=signed(data,'fixture-first')
        assert client.post('/v1/webhooks/razorpay',content=raw,headers=headers).status_code==200
        old={**data,'event':'payment.authorized'}
        raw,headers=signed(old,'fixture-older')
        assert client.post('/v1/webhooks/razorpay',content=raw,headers=headers).status_code==200
        with Session(s.engine) as session:
            assert session.get(Resource,a.args.payment_id).amount_refunded_paise==1000
        assert client.get('/not-an-endpoint').json()['reason']=='ENDPOINT_NOT_ALLOWED'


def test_all_payment_version_components_change_hash():
    payment=ProviderPayment(provider_id='pay_fixture1',amount_paise=1000,amount_refunded_paise=0,currency='INR',status='captured')
    for change in ({'provider_id':'pay_fixture2'},{'amount_paise':1001},{'amount_refunded_paise':1},{'status':'authorized'}):
        assert payment.model_copy(update=change).version_hash!=payment.version_hash
