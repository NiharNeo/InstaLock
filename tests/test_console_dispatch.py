"""Fixture-only security and crash-recovery checks for low-intervention operator flow."""
import os
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any
from cryptography.fernet import Fernet
import pytest
from sqlalchemy import select,update
from sqlalchemy.orm import Session
from app.core.dispatch import dispatch_pending,load_dispatch_cipher
from app.core.receipts import verify_chain
from intentlock.db import ApprovalDispatch,Proposal,UsedGrant,Operation,Ticket
from test_policy import fixture_policy_document,fixture_v1_action
from test_executor import fixture_executor
from test_gateway_v1 import fixture_gateway,submit,preview


@pytest.fixture
def fixture_dispatch(fixture_executor: Any,tmp_path: Any,monkeypatch: Any) -> Any:
    """Configure a protected queue key and real executor logic with fixture provider I/O."""
    c,provider,service,action,token=fixture_executor
    key=tmp_path/'fixture-dispatch.key';key.write_bytes(Fernet.generate_key());key.chmod(0o600)
    monkeypatch.setenv('DISPATCH_KEY_FILE',str(key))
    def call(path: str,body: dict[str,Any]) -> dict[str,Any]:
        assert path=='internal/execute'
        return service.execute(action,body['grant_token'],body['idempotency_key'],body['service_id'])
    c['app'].state.gateway.executor=SimpleNamespace(call=call)
    proposal=submit(c).json()['proposal_id']
    assert preview(c,proposal).status_code==200
    return c,provider,service,proposal,key


def queue(c: Any,proposal: str,headers: Any = None,body: Any = None) -> Any:
    """Post an explicit fixture human approval to the queueing endpoint."""
    return c['client'].post('/v1/proposals/'+proposal+'/approve-and-execute',headers=headers or c['approval'],json={} if body is None else body)


def test_one_click_encrypted_dispatch_exactly_once(fixture_dispatch: Any) -> None:
    """No provider call before consent; one exact refund, no token exposed or retained."""
    c,provider,service,proposal,key=fixture_dispatch
    response=queue(c,proposal)
    assert response.status_code==202,response.text
    assert 'grant_token' not in response.json()
    assert provider.calls==0
    with Session(c['engine']) as session:
        job=session.get(ApprovalDispatch,proposal)
        assert not job.token_ciphertext.startswith('eyJ')
        token=load_dispatch_cipher().decrypt(job.token_ciphertext.encode()).decode()
        assert token.count('.')==2
    dispatch_pending(c['app'].state.gateway)
    dispatch_pending(c['app'].state.gateway)
    assert provider.calls==1
    with Session(c['engine']) as session,session.begin():
        job=session.get(ApprovalDispatch,proposal)
        assert job.status=='DELIVERED' and job.token_ciphertext==''
        assert session.get(Operation,job.operation_id).status=='DONE'
        assert verify_chain(session,'tenant-a')['valid']
    assert queue(c,proposal).json()['reason']=='DISPATCH_ALREADY_QUEUED'
    assert provider.calls==1


def test_dispatch_recovers_lost_executor_reply(fixture_dispatch: Any) -> None:
    """Crash after provider success leaves encrypted retry; identical key returns same result."""
    c,provider,service,proposal,key=fixture_dispatch
    assert queue(c,proposal).status_code==202
    gateway=c['app'].state.gateway
    call=gateway.executor.call
    def lost(path: str,body: dict[str,Any]) -> dict[str,Any]:
        call(path,body)
        raise ConnectionError('fixture lost response')
    gateway.executor.call=lost
    dispatch_pending(gateway)
    with Session(c['engine']) as session,session.begin():
        job=session.get(ApprovalDispatch,proposal)
        assert job.status=='QUEUED' and job.token_ciphertext
        session.execute(update(ApprovalDispatch).values(next_attempt_at=0))
    gateway.executor.call=call
    dispatch_pending(gateway)
    assert provider.calls==1
    with Session(c['engine']) as session:
        assert session.get(ApprovalDispatch,proposal).status=='DELIVERED'


@pytest.mark.parametrize('failure',['agent','csrf','preview','extra','missing_key','public_key_file'])
def test_dispatch_requires_real_human_review(fixture_dispatch: Any,monkeypatch: Any,failure: str) -> None:
    """Invalid requests cannot mint consent or enqueue execution."""
    c,provider,service,proposal,key=fixture_dispatch
    headers=dict(c['approval']);body={}
    if failure=='agent':headers=c['agent']
    if failure=='csrf':headers.pop('X-CSRF-Token')
    if failure=='preview':proposal=submit(c).json()['proposal_id']
    if failure=='extra':body={'action_digest':'fixture-client-digest'}
    if failure=='missing_key':monkeypatch.delenv('DISPATCH_KEY_FILE')
    if failure=='public_key_file':key.chmod(0o644)
    response=queue(c,proposal,headers,body)
    assert response.status_code>=400,response.text
    assert provider.calls==0
    with Session(c['engine']) as session:
        assert session.get(ApprovalDispatch,proposal) is None
        assert session.get(Proposal,proposal).status=='PENDING'


def test_parallel_dispatch_workers_lease_one_handoff(fixture_dispatch: Any) -> None:
    """Multiple trusted worker instances cannot duplicate an approved effect."""
    c,provider,service,proposal,key=fixture_dispatch
    assert queue(c,proposal).status_code==202
    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(lambda _:dispatch_pending(c['app'].state.gateway),range(10)))
    assert provider.calls==1


def test_dispatch_never_mints_grant(fixture_dispatch: Any,monkeypatch: Any) -> None:
    """Dispatch needs only the already signed encrypted token; no signing API is called."""
    c,provider,service,proposal,key=fixture_dispatch
    assert queue(c,proposal).status_code==202
    def forbidden(*args: Any,**kwargs: Any) -> Any:
        raise AssertionError('dispatcher must not issue consent')
    monkeypatch.setattr('app.core.grants.GrantService.issue_grant',forbidden)
    dispatch_pending(c['app'].state.gateway)
    assert provider.calls==1


def test_console_auth_scope_and_secret_exclusion(fixture_dispatch: Any) -> None:
    """Only operator sessions see their tenant rows, never raw tickets or queued grants."""
    c,provider,service,proposal,key=fixture_dispatch
    assert queue(c,proposal).status_code==202
    assert c['client'].get('/v1/console',headers=c['agent']).status_code==401
    assert c['client'].get('/v1/console?tenant_id=other',headers=c['operator']).status_code==400
    response=c['client'].get('/v1/console',headers=c['operator'])
    assert response.status_code==200,response.text
    body=response.json()
    assert body['tenant_id']=='tenant-a'
    assert {r['id'] for r in body['proposals']}>= {proposal}
    assert 'token_ciphertext' not in response.text and 'grant_token' not in response.text
    assert all('text' not in row for row in body['tickets'])


def test_corrupt_encrypted_dispatch_fails_closed(fixture_dispatch: Any) -> None:
    """Ciphertext changes cannot authorize a refund; failure is recorded without losing consent."""
    c,provider,service,proposal,key=fixture_dispatch
    assert queue(c,proposal).status_code==202
    with Session(c['engine']) as session,session.begin():
        session.get(ApprovalDispatch,proposal).token_ciphertext='corrupted-fixture'
    dispatch_pending(c['app'].state.gateway)
    assert provider.calls==0
    with Session(c['engine']) as session,session.begin():
        job=session.get(ApprovalDispatch,proposal)
        assert job.status=='QUEUED' and job.reason=='DISPATCH_DECRYPT_FAILED'
        assert verify_chain(session,'tenant-a')['valid']


def test_console_excludes_other_tenant_rows(fixture_dispatch: Any) -> None:
    """Even a foreign proposal with a similar identifier is absent from the operator list."""
    c,provider,service,proposal,key=fixture_dispatch
    with Session(c['engine']) as session,session.begin():
        own=session.get(Proposal,proposal)
        session.add(Proposal(id='fixture-foreign',tenant_id='tenant-other',service_id=own.service_id,action={**own.action,'tenant_id':'tenant-other'},action_digest=own.action_digest,policy_version=own.policy_version,status='PENDING',created_at=int(time.time())))
    result=c['client'].get('/v1/console',headers=c['operator'])
    assert result.status_code==200
    assert 'fixture-foreign' not in result.text
    denied=queue(c,'fixture-foreign')
    assert denied.status_code>=400
    assert provider.calls==0


def test_queue_and_consent_roll_back_together(fixture_dispatch: Any,monkeypatch: Any) -> None:
    """A failed encrypted handoff write must roll back the grant and human approval."""
    c,provider,service,proposal,key=fixture_dispatch
    original=Fernet.encrypt
    def unavailable(self: Any,data: bytes) -> bytes:
        raise OSError('fixture encryption failure')
    monkeypatch.setattr(Fernet,'encrypt',unavailable)
    result=queue(c,proposal)
    assert result.status_code>=400
    with Session(c['engine']) as session:
        row=session.get(Proposal,proposal)
        assert row.status=='PENDING' and row.grant_id is None
        assert session.get(ApprovalDispatch,proposal) is None
    assert provider.calls==0


def test_tampered_grant_cannot_dispatch_refund(fixture_dispatch: Any) -> None:
    """Even valid queue encryption cannot make a modified grant signature authoritative."""
    c,provider,service,proposal,key=fixture_dispatch
    assert queue(c,proposal).status_code==202
    cipher=load_dispatch_cipher()
    with Session(c['engine']) as session,session.begin():
        job=session.get(ApprovalDispatch,proposal)
        token=cipher.decrypt(job.token_ciphertext.encode()).decode()
        parts=token.split('.')
        parts[2]=('A' if parts[2][0]!='A' else 'B')+parts[2][1:]
        job.token_ciphertext=cipher.encrypt('.'.join(parts).encode()).decode()
    dispatch_pending(c['app'].state.gateway)
    assert provider.calls==0
    with Session(c['engine']) as session:
        job=session.get(ApprovalDispatch,proposal)
        assert job.status=='FAILED' and job.reason=='BAD_SIGNATURE'
        assert not job.token_ciphertext


def test_same_origin_session_resumption_keeps_csrf_protection(fixture_dispatch: Any,monkeypatch: Any) -> None:
    """A valid HttpOnly session resumes writes without pasted CSRF; agent and cross-site cannot."""
    c,provider,service,proposal,key=fixture_dispatch
    monkeypatch.setenv('SESSION_CSRF_SECRET','fixture-session-csrf-secret-'+'x'*32)
    endpoint='/v1/session'
    assert c['client'].get(endpoint,headers=c['agent']).status_code==401
    assert c['client'].get(endpoint,headers={**c['operator'],'Origin':'https://attacker.invalid'}).status_code==403
    response=c['client'].get(endpoint,headers=c['operator'])
    assert response.status_code==200,response.text
    csrf=response.json()['csrf_token']
    assert csrf==c['client'].get(endpoint,headers=c['operator']).json()['csrf_token']
    assert 'session_token' not in response.json()
    headers={**c['approval'],'X-CSRF-Token':csrf}
    result=queue(c,proposal,headers)
    assert result.status_code==202,result.text
    assert provider.calls==0


def test_derived_csrf_bound_to_exact_session(fixture_dispatch: Any,monkeypatch: Any) -> None:
    """Another legitimate human session's CSRF token cannot approve on this session."""
    from app.auth.service import provision_session
    c,provider,service,proposal,key=fixture_dispatch
    monkeypatch.setenv('SESSION_CSRF_SECRET','fixture-session-csrf-secret-'+'x'*32)
    with Session(c['engine']) as session,session.begin():
        token,csrf=provision_session(session,'human','gateway-kid',3600)
    other=c['client'].get('/v1/session',headers={'Cookie':'intentlock_session='+token})
    assert other.status_code==200
    result=queue(c,proposal,{**c['approval'],'X-CSRF-Token':other.json()['csrf_token']})
    assert result.status_code==403 and result.json()['reason']=='CSRF_INVALID'
    assert provider.calls==0
