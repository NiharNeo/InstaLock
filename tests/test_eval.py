"""Fixture-only tests of eval generation/provenance. These are not live benchmark runs."""
import base64
from collections import Counter
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any
from unittest.mock import patch
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.canonical import _load_json
from app.core.timing import duration_ns, provider_span, provider_spans
from app.executor.eval_probe import probe
from app.executor.razorpay import RazorpayTestAdapter
from intentlock.db import EvalRun, UsedGrant
from tools.eval.captures import read_secret, validate_capture, write_secret
from tools.eval.cases import KINDS, suite, wire
from tools.eval.contracts import Capture, Plan
from tools.eval.observer import delta
from tools.eval.runner import percentiles
from test_gateway_v1 import fixture_gateway, authorized
from test_policy import fixture_policy_document, fixture_v1_action
from test_executor import fixture_executor


@pytest.fixture
def fixture_capture(fixture_gateway: Any):
    c=fixture_gateway
    proposal,token=authorized(c)
    return c,Capture(name='fixture-base',role='fresh',ticket_id='ticket',proposal_id=proposal,action=c['action'],grant_token=token)


@pytest.fixture
def fixture_plan(fixture_capture):
    c,capture=fixture_capture
    records=[capture]
    alternate=capture.model_copy(deep=True,update={'name':'fixture-alt'})
    records.append(alternate)
    for role in ('expired','used','different_tool'):
        records.append(capture.model_copy(deep=True,update={'name':'fixture-'+role,'role':role}))
    records.extend(capture.model_copy(deep=True,update={'name':'fixture-stale-'+str(n),'role':'stale'}) for n in range(4))
    return Plan(captures=records,base_id=capture.name,alternate_id=alternate.name,foreign_payment_id='pay_fixtureForeign',valid_ids=[capture.name]*40,concurrency_id=capture.name)


def test_sixty_real_capture_mutations_and_exact_category_counts(fixture_plan):
    cases=suite(fixture_plan)
    assert len(cases)==60
    counts=Counter(case.kind for case in cases)
    assert set(counts)==set(KINDS)
    assert all(counts[kind]==(4 if index<12 else 3) for index,kind in enumerate(KINDS))
    assert len({case.index for case in cases})==60
    assert len({case.capture.name for case in cases if case.kind=='stale_after_webhook'})==4


@pytest.mark.parametrize('kind',['missing_grant','forged_signature','alg_none','hs256_confusion','float_amount','duplicate_keys','unicode_lookalike','oversized_args','changed_destination','changed_amount','changed_payment_id','other_tenant_payment'])
def test_mutations_preserve_or_break_wire_intentionally(fixture_plan,kind):
    case=next(case for case in suite(fixture_plan) if case.kind==kind)
    action=case.capture.action.model_dump(mode='json')
    raw=wire(case,action,case.capture.grant_token,alternate_payment='pay_fixtureAlt',foreign_payment='pay_fixtureForeign',foreign_tenant='tenant-other',public_key=b'fixture public key')
    if kind=='oversized_args':
        assert len(raw)>65536
    elif kind=='duplicate_keys':
        with pytest.raises(ValueError):
            _load_json(raw)
    else:
        body=json.loads(raw)
        if kind=='missing_grant':
            assert 'grant_token' not in body
        if kind=='float_amount':
            assert type(body['action']['args']['amount_paise']) is float
        if kind=='forged_signature':
            assert body['grant_token']!=case.capture.grant_token
        if kind=='other_tenant_payment':
            assert body['action']['tenant_id']=='tenant-other'
    assert case.capture.action.model_dump(mode='json')==action


def test_capture_requires_actual_signed_ticket_proposal_and_grant(fixture_capture):
    c,capture=fixture_capture
    with Session(c['engine']) as session:
        validate_capture(session,capture,'tenant-a')
        with pytest.raises(ValueError,match='CAPTURE_RESOURCE_PROVENANCE'):
            validate_capture(session,capture.model_copy(update={'ticket_id':'not-a-real-ticket'}),'tenant-a')
        with pytest.raises(ValueError,match='CAPTURE_GRANT_PROVENANCE'):
            validate_capture(session,capture.model_copy(update={'grant_token':capture.grant_token[:-4]+'xxxx'}),'tenant-a')
        with pytest.raises(ValueError,match='REAL_POST_APPROVAL_WEBHOOK_REQUIRED'):
            validate_capture(session,capture.model_copy(update={'role':'stale'}),'tenant-a')


def test_capture_files_private_and_not_overwritten(tmp_path):
    path=tmp_path/'fixture-capture.json'
    write_secret(path,{'fixture':'security artifact'})
    assert os.stat(path).st_mode&0o777==0o600
    assert read_secret(path)
    with pytest.raises(FileExistsError):
        write_secret(path,{})
    path.chmod(0o644)
    with pytest.raises(ValueError):
        read_secret(path)


def test_provider_delta_counts_ids_even_when_balance_has_not_settled():
    before={'db_ids':[],'payments':{'pay_fixture':{'payment':{'amount_refunded_paise':0},'refunds':[]}}}
    after=deepcopy(before)
    after['payments']['pay_fixture']['refunds']=[{'provider_id':'rfnd_fixture','status':'pending'}]
    result=delta(before,after)
    assert len(result['provider_refunds'])==1
    assert result['balance_delta_paise']['pay_fixture']==0


def test_timing_is_real_and_union_avoids_double_subtraction():
    spans=[]
    token=provider_spans.set(spans)
    try:
        with provider_span():
            time.sleep(0.005)
    finally:
        provider_spans.reset(token)
    assert duration_ns(spans)>=4000000
    assert duration_ns([(10,20),(15,25),(25,30)])==20
    with pytest.raises(ValueError):
        duration_ns([(20,10)])
    assert percentiles([])['p95_ms'] is None
    assert percentiles([1_000_000,2_000_000,3_000_000])=={'samples':3,'p50_ms':2.0,'p95_ms':3.0,'p99_ms':3.0}


def test_probe_is_actual_test_api_and_baseline_requires_local_flag(fixture_executor):
    c,p,s,a,t=fixture_executor
    requests=[]
    def transport(request):
        requests.append(request)
        if request.url.path.endswith('/refunds'):
            return httpx.Response(200,json={'count':0,'items':[]})
        return httpx.Response(200,json={'id':'pay_fixture1','amount':100000,'amount_refunded':0,'currency':'INR','status':'captured'})
    adapter=RazorpayTestAdapter(s.settings,transport=httpx.MockTransport(transport))
    try:
        evidence=probe(s.settings,adapter,{'op':'snapshot','tenant_id':'tenant-a','payment_ids':['pay_fixture1']},bypass=False)
        assert evidence['mode']=='razorpay-test' and len(requests)==2
        with pytest.raises(ValueError):
            probe(s.settings,adapter,{'op':'baseline','tenant_id':'tenant-a'},bypass=False)
        with pytest.raises(ValueError):
            probe(s.settings,adapter,{'op':'snapshot','tenant_id':'tenant-other','payment_ids':['pay_fixture1']},bypass=False)
    finally:
        adapter.close()


def test_metrics_history_is_operator_only_and_tenant_scoped(fixture_gateway):
    c=fixture_gateway
    with Session(c['engine']) as session,session.begin():
        for tenant,name in [('tenant-a','fixture-own'),('tenant-other','fixture-other')]:
            session.add(EvalRun(id=name,tenant_id=tenant,git_sha='a'*40,started_at=1,finished_at=2,status='BLOCKED',summary={'stop_reason':'FIXTURE_ONLY'},cases=[]))
    assert c['client'].get('/v1/eval-runs',headers=c['agent']).status_code==401
    response=c['client'].get('/v1/eval-runs',headers=c['operator'])
    assert response.status_code==200,response.text
    assert [r['id'] for r in response.json()['items']]==['fixture-own']
    assert c['client'].get('/v1/eval-runs/fixture-other',headers=c['operator']).status_code==404
    assert c['client'].get('/v1/eval-runs?tenant_id=tenant-other',headers=c['operator']).status_code==400
    assert c['client'].get('/v1/eval-runs?limit=0',headers=c['operator']).status_code==400
    assert c['client'].get('/v1/eval-runs/fixture-own',headers=c['operator']).json()['cases']==[]


def test_missing_git_records_blocked_run_without_fabricated_sha(fixture_gateway,tmp_path,monkeypatch,capsys):
    from tools.eval.__main__ import main
    c=fixture_gateway
    monkeypatch.setenv('DATABASE_URL',c['config'].database_url)
    monkeypatch.setenv('EVAL_TENANT_ID','tenant-a')
    monkeypatch.setattr('sys.argv',['eval','run','--plan',str(tmp_path/'nonexistent-secret-plan.json')])
    with patch('tools.eval.__main__.git_sha',return_value=None),pytest.raises(SystemExit) as stopped:
        main()
    assert stopped.value.code==2
    with Session(c['engine']) as session:
        row=session.scalar(select(EvalRun))
        assert row.status=='BLOCKED' and row.git_sha is None
        assert row.summary['stop_reason']=='GIT_SHA_UNAVAILABLE'
        assert row.cases==[]
    assert 'not measured' in capsys.readouterr().out


def test_actual_adapter_spans_forwarded_to_gateway_headers(fixture_executor):
    from app.executor.main import create_app
    from app.executor.client import ExecutorClient
    from fastapi.testclient import TestClient
    from test_gateway_v1 import execute
    c,p,s,a,token=fixture_executor
    def transport(request):
        time.sleep(0.005)  # Fixture-only wire delay; production has no stub or sleep path.
        if request.method=='POST':
            payload=json.loads(request.content)
            refund=p.create_refund('pay_fixture1',payload['amount'],request.headers['X-Refund-Idempotency'])
            return httpx.Response(200,json={'id':refund.provider_id,'payment_id':refund.payment_id,'amount':refund.amount_paise,'currency':refund.currency,'status':refund.status,'receipt':refund.receipt})
        payment=p.get_payment('pay_fixture1')
        return httpx.Response(200,json={'id':payment.provider_id,'amount':payment.amount_paise,'amount_refunded':payment.amount_refunded_paise,'currency':payment.currency,'status':payment.status})
    adapter=RazorpayTestAdapter(s.settings,transport=httpx.MockTransport(transport))
    with TestClient(create_app(s.settings,provider=adapter)) as executor:
        def rpc(request):
            response=executor.request(request.method,request.url.path,content=request.content,headers=dict(request.headers))
            return httpx.Response(response.status_code,content=response.content,headers=dict(response.headers))
        remote=ExecutorClient('http://executor:8001',s.settings.internal_token)
        remote.client.close()
        remote.client=httpx.Client(base_url='http://executor:8001/',headers={'Authorization':'Bearer '+s.settings.internal_token},transport=httpx.MockTransport(rpc))
        c['app'].state.gateway.executor=remote
        try:
            response=execute(c,token)
            assert response.status_code==200,response.text
            assert response.headers['X-IntentLock-Timing-Valid']=='1'
            provider=int(response.headers['X-IntentLock-Provider-Ns'])
            assert provider>=15_000_000
            assert int(response.headers['X-IntentLock-Gateway-Ns'])>=provider
            assert '_provider_ns' not in response.json()
        finally:
            remote.client.close()
    adapter.close()


def test_metrics_pagination_does_not_load_case_payloads(fixture_gateway):
    """Fixture history pages must exclude large case JSON even during cursor lookup."""
    from sqlalchemy import event
    c=fixture_gateway
    with Session(c['engine']) as session,session.begin():
        for number in range(3):
            session.add(EvalRun(id=f'fixture-page-{number}',tenant_id='tenant-a',git_sha=None,started_at=number,finished_at=4,status='PASS',summary={},cases=[{'fixture_payload':'x'*10000}]))
    statements=[]
    def capture(connection,cursor,statement,parameters,context,executemany):
        if statement.lstrip().upper().startswith('SELECT') and 'eval_runs' in statement:
            statements.append(statement)
    event.listen(c['app'].state.gateway.engine,'before_cursor_execute',capture)
    try:
        first=c['client'].get('/v1/eval-runs?limit=1&status=PASS',headers=c['operator'])
        assert first.status_code==200,first.text
        second=c['client'].get('/v1/eval-runs',params={'limit':1,'cursor':first.json()['next_cursor'],'status':'PASS'},headers=c['operator'])
        assert second.status_code==200,second.text
        assert [first.json()['items'][0]['id'],second.json()['items'][0]['id']]==['fixture-page-2','fixture-page-1']
        assert statements and all('eval_runs.cases' not in sql for sql in statements)
    finally:
        event.remove(c['app'].state.gateway.engine,'before_cursor_execute',capture)


def test_observer_batches_database_payment_lookup(fixture_executor):
    """Fixture observer uses two SQL reads regardless of repeated payment references."""
    from sqlalchemy import event
    from tools.eval.observer import Observer
    c,p,s,a,token=fixture_executor
    observer=Observer(c['engine'],{'tenant-a':['fixture-probe']})
    statements=[]
    def capture(connection,cursor,statement,parameters,context,executemany):
        if statement.lstrip().upper().startswith('SELECT'):
            statements.append(statement)
    event.listen(c['engine'],'before_cursor_execute',capture)
    try:
        evidence={'mode':'razorpay-test','tenant_id':'tenant-a','payments':{'pay_fixture1':{}}}
        with patch.object(observer,'call',return_value=evidence):
            assert observer.snapshot(['pay_fixture1']*50)['payments']==evidence['payments']
        assert len(statements)==2
        with pytest.raises(ValueError,match='OBSERVED_PAYMENT_NOT_IN_DATABASE'):
            observer.snapshot(['fixture-missing'])
    finally:
        event.remove(c['engine'],'before_cursor_execute',capture)
