"""Operator, tenant isolation, and policy lifecycle tests."""
import json
import os
import time
from dataclasses import replace
from typing import Any
from unittest.mock import patch
import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from intentlock.config import Settings
from intentlock.db import Order, Refund, Ticket
from intentlock.operator import import_records
from intentlock.schema import canonical, parse_json
from test_security import post, assert_denied


def test_agent_context_tenant_isolation(fixture_context: Any) -> None:
    cfg, engine, _, client = fixture_context
    with Session(engine) as session, session.begin():
        session.add(Order(id='other', tenant_id='tenant-b', paid_paise=1000, refunded_paise=0, currency='INR', destination='other', version=1))
        session.flush()
        session.add(Ticket(id='other', tenant_id='tenant-b', order_id='other', text='private'))
    response = client.get('/api/agent/context',headers={'Authorization':'Bearer '+cfg.agent_token})
    assert [o['id'] for o in response.json()['orders']] == ['order']
    assert [t['id'] for t in response.json()['tickets']] == ['ticket']
    assert 'users' not in response.json()
    assert client.get('/api/agent/context').status_code == 401


def test_expiry_boundary(fixture_context: Any, fixture_sign: Any) -> None:
    now = int(time.time())
    with patch('intentlock.gateway.time.time', return_value=now):
        assert_denied(fixture_context, post(fixture_context, fixture_sign(issued_at=now-120, expires_at=now)), 'GRANT_TIME_INVALID')


def test_future_grant(fixture_context: Any, fixture_sign: Any) -> None:
    now = int(time.time())
    assert_denied(fixture_context, post(fixture_context, fixture_sign(issued_at=now+60, expires_at=now+120)), 'GRANT_TIME_INVALID')


def test_denial_does_not_burn_grant(fixture_context: Any, fixture_sign: Any) -> None:
    body = fixture_sign()
    body['action']['amount_paise'] += 1
    assert_denied(fixture_context, post(fixture_context, body), 'ACTION_MISMATCH')
    assert post(fixture_context, fixture_sign()).json()['reason'] == 'AUTHORIZED'


def test_state_is_empty_on_new_database(tmp_path: Any, fixture_context: Any) -> None:
    from intentlock.api import create_app
    from intentlock.db import Base, engine_for
    from fastapi.testclient import TestClient
    cfg = replace(fixture_context[0],database_url='sqlite:///'+str(tmp_path/'empty.db'))
    engine = engine_for(cfg.database_url)
    Base.metadata.create_all(engine)
    with TestClient(create_app(cfg)) as client:
        result = client.get('/api/state',headers={'Authorization':'Bearer '+cfg.operator_token})
        assert all(rows == [] for rows in result.json().values())
    engine.dispose()


@pytest.mark.parametrize('value', [1.0, True, '1'])
def test_import_rejects_money_coercion(fixture_context: Any, tmp_path: Any, monkeypatch: Any, value: Any) -> None:
    cfg = fixture_context[0]
    monkeypatch.setenv('DATABASE_URL',cfg.database_url)
    path = tmp_path/'fixture-import.json'
    path.write_text(json.dumps({'users':[], 'orders':[{'id':'new','tenant_id':'tenant-a','paid_paise':value,'refunded_paise':0,'currency':'INR','destination':'original','version':1}], 'tickets':[]}))
    with pytest.raises(ValidationError):
        import_records(path)


def test_import_real_record_contract(fixture_context: Any, tmp_path: Any, monkeypatch: Any) -> None:
    cfg, engine, _, _ = fixture_context
    monkeypatch.setenv('DATABASE_URL',cfg.database_url)
    path = tmp_path/'fixture-import.json'
    path.write_text(json.dumps({'users':[], 'orders':[{'id':'new','tenant_id':'tenant-a','paid_paise':1,'refunded_paise':0,'currency':'INR','destination':'original','version':1}], 'tickets':[]}))
    import_records(path)
    with Session(engine) as session:
        assert session.get(Order,'new').paid_paise == 1
    with pytest.raises(Exception):
        import_records(path) # Insert-only; never overwrite balances.


def test_policy_environment_validation(monkeypatch: Any) -> None:
    values = {'DATABASE_URL':'sqlite://','AGENT_TOKEN':'a'*40,'OPERATOR_TOKEN':'o'*40,'AGENT_TENANT':'tenant','POLICY_VERSION':'p1','MAX_REFUND_PAISE':'100','MAX_GRANT_SECONDS':'300'}
    for key, value in values.items():
        monkeypatch.setenv(key,value)
    assert Settings.from_env().max_refund_paise == 100
    monkeypatch.setenv('OPERATOR_TOKEN','a'*40)
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.delenv('AGENT_TOKEN')
    with pytest.raises(KeyError):
        Settings.from_env()


def test_duplicate_headers_are_ambiguous(fixture_context: Any, fixture_sign: Any) -> None:
    cfg, _, _, client = fixture_context
    response = client.post('/api/execute',content=canonical(fixture_sign()),headers=[('Authorization','Bearer '+cfg.agent_token),('Authorization','Bearer '+cfg.operator_token),('Content-Type','application/json')])
    assert_denied(fixture_context,response,'AMBIGUOUS_HEADERS')


def test_audit_contains_no_ticket_text_or_token(fixture_context: Any, fixture_sign: Any) -> None:
    result = post(fixture_context,fixture_sign())
    text = json.dumps(result.json())
    assert 'IGNORE POLICY' not in text and fixture_context[0].agent_token not in text
    assert result.headers['cache-control'] == 'no-store'
