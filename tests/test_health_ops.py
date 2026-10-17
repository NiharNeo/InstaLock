"""Fixture-only deployment and readiness checks; no live account or business seeding."""
import json
from pathlib import Path
from typing import Any
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from app.executor.main import create_app
from intentlock.db import Receipt,Operation
from test_policy import fixture_policy_document,fixture_v1_action
from test_gateway_v1 import fixture_gateway
from test_executor import fixture_executor
from tools.ops.local_stack import read_protected,write_protected,snapshot


def test_gateway_readiness_no_financial_or_audit_writes(fixture_gateway: Any) -> None:
    """Infrastructure probes report real readiness without granting or recording tool decisions."""
    c=fixture_gateway
    with Session(c['engine']) as session:
        before=session.scalar(select(func.count()).select_from(Receipt))
    assert c['client'].get('/health/live').json()=={'status':'live'}
    result=c['client'].get('/health/ready')
    assert result.status_code==200 and result.json()=={'status':'ready','component':'gateway'}
    with Session(c['engine']) as session:
        assert session.scalar(select(func.count()).select_from(Receipt))==before
        assert session.scalar(select(func.count()).select_from(Operation))==0


def test_gateway_executor_unavailable_is_not_ready(fixture_gateway: Any) -> None:
    """A failed authenticated dependency check must not report healthy or leak diagnostics."""
    c=fixture_gateway
    def unavailable(*args: Any) -> Any:
        raise RuntimeError('fixture-private-diagnostic')
    c['app'].state.gateway.executor=SimpleNamespace(call=unavailable)
    result=c['client'].get('/health/ready')
    assert result.status_code==503 and result.json()['reason']=='READINESS_UNAVAILABLE'
    assert 'fixture-private' not in result.text


def test_executor_health_requires_internal_auth(fixture_executor: Any) -> None:
    """The gateway health RPC uses executor auth; no provider request or refund occurs."""
    c,provider,service,action,token=fixture_executor
    with TestClient(create_app(service.settings,provider=provider)) as client:
        assert client.get('/health/ready').status_code==200
        assert client.post('/internal/health',json={}).status_code==401
        headers={'Authorization':'Bearer '+service.settings.internal_token}
        assert client.post('/internal/health',json={},headers=headers).json()=={'status':'ready'}
        assert client.post('/internal/health',json={'extra':True},headers=headers).status_code==400
        assert provider.calls==0


def test_protected_ops_files_reject_symlink_and_public_mode(tmp_path: Path) -> None:
    """Administrative input cannot follow a symlink or accept shared-readable secrets."""
    file=tmp_path/'fixture-secret';write_protected(file,b'fixture-security-material')
    assert read_protected(file)==b'fixture-security-material'
    link=tmp_path/'fixture-link';link.symlink_to(file)
    with pytest.raises(OSError):read_protected(link)
    file.chmod(0o644)
    with pytest.raises(ValueError):read_protected(file)


def test_snapshot_copies_actual_fixture_ledger(fixture_gateway: Any,tmp_path: Path) -> None:
    """SQLite backup preserves records and does not substitute an empty deployment database."""
    import sqlite3
    c=fixture_gateway
    runtime=tmp_path/'fixture-runtime';runtime.mkdir(mode=0o700)
    write_protected(runtime/'gateway-env.json',json.dumps({'DATABASE_URL':c['config'].database_url}).encode())
    destination=snapshot(runtime)
    with sqlite3.connect(destination) as connection:
        assert connection.execute('SELECT id FROM orders').fetchall()==[('order',)]
        assert connection.execute('PRAGMA integrity_check').fetchone()==('ok',)
    assert destination.stat().st_mode & 0o077==0


def test_volume_copy_never_overwrites_different_data(tmp_path: Path) -> None:
    """An attempted second import cannot replace an existing ledger or secret."""
    from tools.ops.initialize_volumes import copy_once
    source=tmp_path/'fixture-new';source.write_bytes(b'fixture-new-data')
    destination=tmp_path/'fixture-existing';destination.write_bytes(b'fixture-existing-data')
    with pytest.raises(ValueError,match='EXISTING_VOLUME_CONTENT_DIFFERS'):
        copy_once(source,destination)
    assert destination.read_bytes()==b'fixture-existing-data'


def test_generated_compose_isolates_agent_and_protects_volumes(fixture_gateway: Any,tmp_path: Path) -> None:
    """Real service-shaped fixture config cannot inject DB/provider/signing access into agent."""
    import os
    import yaml
    from cryptography.fernet import Fernet
    from tools.ops.local_stack import prepare
    c=fixture_gateway
    runtime=tmp_path/'fixture-runtime';runtime.mkdir(mode=0o700)
    dispatch=runtime/'fixture-dispatch.key';write_protected(dispatch,Fernet.generate_key())
    c['policy_path'].chmod(0o600)
    common={'DATABASE_URL':c['config'].database_url,'POLICY_FILE':str(c['policy_path']),'GRANT_ISSUER':'fixture-issuer','EXECUTOR_AUTH_TOKEN':'fixture-internal-'+'x'*32,'RECEIPT_PRIVATE_KEY_PEM':os.environ['RECEIPT_PRIVATE_KEY_PEM']}
    gateway={**common,'GRANT_PRIVATE_KEY_PEM':os.environ['GRANT_PRIVATE_KEY_PEM'],'DISPATCH_KEY_FILE':str(dispatch),'INTAKE_RATE_SECRET':'fixture-intake-'+'x'*32,'SESSION_CSRF_SECRET':'fixture-session-'+'x'*32}
    executor={**common,'EXECUTOR_TENANT_ID':'tenant-a','RAZORPAY_ACCOUNT_ID':'acc_fixture','RAZORPAY_KEY_ID':'rzp_test_fixture','RAZORPAY_KEY_SECRET':'fixture-provider-secret','RAZORPAY_WEBHOOK_SECRET':'fixture-webhook-'+'x'*32}
    agent={'GATEWAY_URL':'http://127.0.0.1:8000','AGENT_SERVICE_KEY':'fixture-agent-'+'x'*40,'GEMINI_API_KEY':'fixture-model-key','GEMINI_MODEL':'fixture-model','DATABASE_URL':'must-not-propagate','RAZORPAY_KEY_SECRET':'must-not-propagate'}
    for name,values in [('gateway',gateway),('executor',executor),('agent',agent)]:
        write_protected(runtime/(name+'-env.json'),json.dumps(values).encode())
    destination=prepare(runtime)
    spec=yaml.safe_load(destination.read_text())
    assert set(spec['services']['agent']['environment'])=={'GATEWAY_URL','AGENT_SERVICE_KEY','GEMINI_API_KEY','GEMINI_MODEL'}
    assert 'volumes' not in spec['services']['agent'] and spec['services']['agent']['read_only']
    assert 'ports' not in spec['services']['executor'] and 'ports' not in spec['services']['gateway']
    assert spec['services']['web']['ports']==['127.0.0.1:8080:8080']
    assert all(volume['external'] for volume in spec['volumes'].values())
    assert destination.stat().st_mode & 0o077==0
    assert prepare(runtime)==destination  # Repreparing must work with the read-only policy copy.


def test_readiness_census_records_blockers_without_financial_calls(fixture_gateway: Any,monkeypatch: Any) -> None:
    """A readiness record is real evidence of missing prerequisites, never a benchmark pass."""
    import httpx
    from intentlock.db import EvalRun,UsedGrant
    from tools.eval.preflight import record_preflight
    c=fixture_gateway
    def get(self: Any,url: str) -> Any:
        assert url=='http://gateway:8000/health/ready'
        return httpx.Response(200,json={'status':'ready'})
    monkeypatch.setattr(httpx.Client,'get',get)
    with Session(c['engine']) as session:
        before=session.scalar(select(func.count()).select_from(UsedGrant))
    identifier=record_preflight(c['engine'],'tenant-a','http://gateway:8000','a'*40)
    with Session(c['engine']) as session:
        row=session.get(EvalRun,identifier)
        assert row.status=='BLOCKED' and row.cases==[]
        assert row.summary['suite_executed'] is False
        assert 'OTHER_TENANT_PAYMENT_AND_EXECUTOR_REQUIRED' in row.summary['missing_prerequisites']
        assert 'VERIFIED_WEBHOOK_HISTORY_REQUIRED' in row.summary['missing_prerequisites']
        assert row.summary['misuse_attempted']==row.summary['valid_attempted']==0
        assert session.scalar(select(func.count()).select_from(UsedGrant))==before
        assert session.scalar(select(func.count()).select_from(Operation))==0


def test_retired_native_ledger_cannot_be_used_as_live_backup(fixture_gateway: Any,tmp_path: Path) -> None:
    """After Docker cutover, an old native file must not masquerade as the current backup."""
    c=fixture_gateway
    runtime=tmp_path/'fixture-retired';runtime.mkdir(mode=0o700)
    write_protected(runtime/'gateway-env.json',json.dumps({'DATABASE_URL':c['config'].database_url}).encode())
    write_protected(runtime/'docker'/'active.json',b'{"active":true}')
    with pytest.raises(ValueError,match='NATIVE_LEDGER_RETIRED_USE_DOCKER_BACKUP'):
        snapshot(runtime)
