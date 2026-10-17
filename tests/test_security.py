"""Regression tests for the trusted boundary, with no live business data."""
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch
import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from intentlock.db import Execution, Order, Receipt, Refund, Ticket, UsedGrant, User
from intentlock.schema import Action, canonical, digest


def post(context: Any, body: dict[str, Any]) -> Any:
    """Submit a fixture proposal with its tenant-scoped gateway token."""
    settings, _, _, client = context
    return client.post('/api/execute', json=body, headers={'Authorization':'Bearer '+settings.agent_token})

def assert_denied(context: Any, response: Any, reason: str, expected_refunded: int = 0) -> None:
    """Assert stable denial, a committed receipt, and no money movement."""
    assert response.status_code == 403
    assert response.json()['reason'] == reason
    _, engine, _, _ = context
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 0
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0
        receipt = session.get(Receipt, response.json()['id'])
        assert receipt and not receipt.allowed and receipt.rule_id and receipt.policy_version
        assert session.get(Order, 'order').refunded_paise == expected_refunded


def test_valid_single_use_retry(fixture_context: Any, fixture_sign: Any) -> None:
    body = fixture_sign()
    first = post(fixture_context, body)
    assert first.json()['reason'] == 'AUTHORIZED'
    retry = post(fixture_context, body)
    assert retry.json()['reason'] == 'IDEMPOTENT_RETRY'
    assert first.json()['refund_id'] == retry.json()['refund_id']
    body['request_id'] = 'new-request'
    assert post(fixture_context, body).json()['reason'] == 'GRANT_USED'
    with Session(fixture_context[1]) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 1
        assert session.scalar(select(func.count()).select_from(Receipt)) == 3
        assert session.get(Order, 'order').version == 2

@pytest.mark.parametrize('field,value', [('amount_paise',49901), ('destination','attacker'), ('order_id','other'), ('ticket_id','other'), ('resource_version',2)])
def test_action_tampering(fixture_context: Any, fixture_sign: Any, field: str, value: Any) -> None:
    body = fixture_sign()
    body['action'][field] = value
    assert_denied(fixture_context, post(fixture_context, body), 'ACTION_MISMATCH')

@pytest.mark.parametrize('field,value', [('amount_paise',1.0), ('amount_paise',True), ('amount_paise','1'), ('amount_paise',0), ('amount_paise',-1), ('amount_paise',9007199254740992), ('resource_version',1.0), ('tool','shell.execute'), ('currency','USD'), ('extra','ignore')])
def test_strict_action_validation(fixture_context: Any, fixture_sign: Any, field: str, value: Any) -> None:
    body = fixture_sign()
    body['action'][field] = value
    assert_denied(fixture_context, post(fixture_context, body), 'INVALID_REQUEST')

@pytest.mark.parametrize('field,value,reason', [('expires_at',1,'GRANT_TIME_INVALID'), ('issued_at',9007199254740000,'GRANT_TIME_INVALID'), ('expires_at',9007199254740000,'GRANT_TIME_INVALID'), ('policy_version','different','POLICY_CHANGED'), ('signer_id','unknown','SIGNER_UNTRUSTED'), ('tenant_id','tenant-b','TENANT_MISMATCH'), ('action_digest','0'*64,'ACTION_MISMATCH')])
def test_signed_grant_constraints(fixture_context: Any, fixture_sign: Any, field: str, value: Any, reason: str) -> None:
    assert_denied(fixture_context, post(fixture_context, fixture_sign(**{field:value})), reason)

@pytest.mark.parametrize('field,value', [('purpose','other'), ('audience','other'), ('alg','HS256'), ('issued_at',1.0)])
def test_grant_schema(fixture_context: Any, fixture_sign: Any, field: str, value: Any) -> None:
    body = fixture_sign()
    body['grant'][field] = value
    assert_denied(fixture_context, post(fixture_context, body), 'INVALID_REQUEST')

@pytest.mark.parametrize('kind', ['forged', 'changed-grant', 'wrong-key', 'bad-base64'])
def test_signature(fixture_context: Any, fixture_sign: Any, kind: str) -> None:
    body = fixture_sign()
    if kind == 'changed-grant':
        body['grant']['grant_id'] = 'different'
    elif kind == 'wrong-key':
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        body['signature'] = base64.b64encode(Ed25519PrivateKey.generate().sign(canonical(body['grant']))).decode()
    else:
        body['signature'] = base64.b64encode(bytes(64)).decode() if kind == 'forged' else '!'*88
    assert_denied(fixture_context, post(fixture_context, body), 'INVALID_SIGNATURE')

@pytest.mark.parametrize('table,values,reason', [(Order,{'version':2},'STALE_RESOURCE'), (Order,{'destination':'changed'},'DESTINATION_MISMATCH'), (Order,{'refunded_paise':90000},'INSUFFICIENT_BALANCE'), (Order,{'tenant_id':'tenant-b'},'TENANT_MISMATCH'), (Ticket,{'tenant_id':'tenant-b'},'TENANT_MISMATCH'), (User,{'active':False},'SIGNER_UNTRUSTED'), (User,{'tenant_id':'tenant-b'},'TENANT_MISMATCH'), (Order,{'currency':'USD'},'CURRENCY_MISMATCH')])
def test_trusted_state(fixture_context: Any, fixture_sign: Any, table: Any, values: Any, reason: str) -> None:
    with Session(fixture_context[1]) as session, session.begin():
        session.execute(update(table).values(**values))
    assert_denied(fixture_context, post(fixture_context, fixture_sign()), reason, values.get('refunded_paise', 0))

def test_policy_limit(fixture_context: Any, fixture_action: Any, fixture_sign: Any) -> None:
    fixture_action['amount_paise'] = 50001
    assert_denied(fixture_context, post(fixture_context, fixture_sign()), 'POLICY_LIMIT')

def test_cross_tenant_agent(fixture_context: Any, fixture_action: Any, fixture_sign: Any) -> None:
    fixture_action['tenant_id'] = 'tenant-b'
    assert_denied(fixture_context, post(fixture_context, fixture_sign(tenant_id='tenant-b')), 'TENANT_MISMATCH')

def test_ticket_association(fixture_context: Any, fixture_sign: Any) -> None:
    with Session(fixture_context[1]) as session, session.begin():
        session.add(Order(id='other', tenant_id='tenant-a', paid_paise=100000, refunded_paise=0, currency='INR', destination='original-payment', version=1))
        session.flush()
        session.execute(update(Ticket).values(order_id='other'))
    assert_denied(fixture_context, post(fixture_context, fixture_sign()), 'TICKET_MISMATCH')

def test_missing_resource(fixture_context: Any, fixture_action: Any, fixture_sign: Any) -> None:
    fixture_action['order_id'] = 'absent'
    assert_denied(fixture_context, post(fixture_context, fixture_sign()), 'RESOURCE_NOT_FOUND')

@pytest.mark.parametrize('raw', [b'{', b'{"action":{},"action":{}}', b'NaN', b'[]', b'{"x":Infinity}', b'\xff'])
def test_malformed_json_audited(fixture_context: Any, raw: bytes) -> None:
    cfg, _, _, client = fixture_context
    response = client.post('/api/execute', content=raw, headers={'Authorization':'Bearer '+cfg.agent_token, 'Content-Type':'application/json'})
    assert_denied(fixture_context, response, 'INVALID_REQUEST')

def test_poisoned_ticket_is_inert(fixture_context: Any, fixture_sign: Any) -> None:
    assert post(fixture_context, fixture_sign()).json()['reason'] == 'AUTHORIZED'
    with Session(fixture_context[1]) as session:
        refund = session.scalar(select(Refund))
        assert refund.amount_paise == 49900 and refund.destination == 'original-payment'

def test_credential_scopes(fixture_context: Any, fixture_sign: Any) -> None:
    cfg, engine, _, client = fixture_context
    for token in ['', cfg.operator_token]:
        response = client.post('/api/execute', json=fixture_sign(), headers={'Authorization':'Bearer '+token})
        assert response.status_code == 401 and response.json()['reason'] == 'UNAUTHENTICATED'
    assert client.get('/api/state', headers={'Authorization':'Bearer '+cfg.agent_token}).status_code == 401
    assert client.post('/api/preview', json=fixture_sign()['action'], headers={'Authorization':'Bearer '+cfg.agent_token}).status_code == 401
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 0

def test_preview_never_authorizes(fixture_context: Any, fixture_sign: Any) -> None:
    cfg, engine, _, client = fixture_context
    action = fixture_sign()['action']
    response = client.post('/api/preview', json=action, headers={'Authorization':'Bearer '+cfg.operator_token})
    assert response.json()['action_digest'] == digest(Action.model_validate(action))
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 0
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0

def test_idempotency_conflict(fixture_context: Any, fixture_sign: Any) -> None:
    assert post(fixture_context, fixture_sign()).json()['allowed']
    result = post(fixture_context, fixture_sign(grant_id='different'))
    assert result.json()['reason'] == 'IDEMPOTENCY_CONFLICT'

def test_audit_failure_rolls_back(fixture_context: Any, fixture_sign: Any) -> None:
    with patch('intentlock.gateway.receipt', side_effect=RuntimeError('audit unavailable')):
        result = post(fixture_context, fixture_sign())
    assert result.status_code == 503 and result.json()['reason'] == 'AUDIT_UNAVAILABLE'
    with Session(fixture_context[1]) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 0
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0
        assert session.get(Order, 'order').refunded_paise == 0

def test_unexpected_error_denies(fixture_context: Any, fixture_sign: Any) -> None:
    with patch('intentlock.gateway.check_action', side_effect=RuntimeError('failure')):
        assert_denied(fixture_context, post(fixture_context, fixture_sign()), 'INTERNAL_ERROR')

def test_concurrent_grant_consumption(fixture_context: Any, fixture_sign: Any) -> None:
    from intentlock.gateway import Denied, execute, record_deny
    cfg, engine, _, _ = fixture_context
    bodies = [fixture_sign() for _ in range(8)]
    for i, body in enumerate(bodies):
        body['request_id'] = 'request-' + str(i)
    def attempt(body: Any) -> Any:
        from intentlock.schema import Envelope
        envelope = Envelope.model_validate(body)
        raw = canonical(envelope)
        try:
            return execute(engine,cfg,raw,envelope)
        except Denied as exc:
            return record_deny(engine,cfg,raw,exc.reason,envelope)
        except Exception:
            return record_deny(engine,cfg,raw,'INTERNAL_ERROR',envelope)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt,bodies))
    assert sum(result['allowed'] for result in results) == 1
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 1
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 1
        assert session.scalar(select(func.count()).select_from(Receipt)) == 8

def test_jcs_order_unicode_and_safe_integer() -> None:
    assert canonical({'b':1,'a':'é'}) == b'{"a":"\xc3\xa9","b":1}'
    assert digest({'a':1,'b':2}) == digest({'b':2,'a':1})
    assert canonical({'text':'e\u0301'}) != canonical({'text':'é'})

def test_size_and_content_type(fixture_context: Any) -> None:
    cfg, _, _, client = fixture_context
    headers = {'Authorization':'Bearer '+cfg.agent_token,'Content-Type':'application/json'}
    assert_denied(fixture_context, client.post('/api/execute', content=b'x'*65537, headers=headers), 'REQUEST_TOO_LARGE')
    headers['Content-Type'] = 'text/plain'
    assert_denied(fixture_context, client.post('/api/execute', content=b'{}', headers=headers), 'INVALID_CONTENT_TYPE')
