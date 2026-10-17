"""HTTP end-to-end security tests with real temporary SQL data and fixture keys."""
import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.auth.service import provision_agent, provision_session, secret_hash
from app.config import GatewaySettings
from app.core.canonical import digest
from app.core.keys import register_public_key
from app.core.policy import PolicyEngine
from app.main import create_app
from intentlock.db import AgentServiceKey, Execution, KeyRegistry, OperatorSession, Order, Payment, Proposal, ProposalPreview, Receipt, Refund, UsedGrant, User
from test_policy import fixture_policy_document, fixture_v1_action


@pytest.fixture
def fixture_gateway(fixture_context: Any, fixture_policy_document: Any, fixture_v1_action: Any, tmp_path: Any, monkeypatch: Any) -> Any:
    """Provision all synthetic service, session, order and payment data only here."""
    cfg, engine, key, _ = fixture_context
    path = tmp_path/'fixture-gateway-policy.yaml'
    path.write_text(yaml.safe_dump(fixture_policy_document))
    register_public_key(engine,'gateway-kid','human','tenant-a',key.public_key())
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    monkeypatch.delenv('GRANT_PRIVATE_KEY_FILE',raising=False)
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PASSWORD',raising=False)
    with Session(engine) as session, session.begin():
        session.add(Payment(id='payment',tenant_id='tenant-a',order_id='order',destination_kind='original_payment',in_flight=False))
        agent = provision_agent(session,'fixture-service','tenant-a','agent-actor',3600)
        cookie,csrf = provision_session(session,'human','gateway-kid',3600)
    config = GatewaySettings(cfg.database_url,path,'fixture-issuer','http://localhost:8080')
    app = create_app(config)
    with TestClient(app) as client:
        yield {'client':client,'engine':engine,'key':key,'agent':{'Authorization':'Bearer '+agent},'operator':{'Cookie':'intentlock_session='+cookie},'approval':{'Cookie':'intentlock_session='+cookie,'X-CSRF-Token':csrf,'Origin':config.origin},'action':fixture_v1_action,'app':app,'config':config,'session_id':secret_hash(cookie),'policy_path':path}


def submit(context: Any, action: Any = None) -> Any:
    """Post the actual fixture proposal through the service-key boundary."""
    return context['client'].post('/v1/proposals',json=action or context['action'],headers=context['agent'])


def preview(context: Any, proposal_id: str) -> Any:
    return context['client'].get('/v1/proposals/'+proposal_id+'/preview',headers=context['operator'])


def approve(context: Any, proposal_id: str, **kwargs: Any) -> Any:
    return context['client'].post('/v1/proposals/'+proposal_id+'/approve',json={},headers=context['approval'],**kwargs)


def authorized(context: Any) -> tuple[str,str]:
    """Exercise real authenticated proposal, live preview, and CSRF approval."""
    submitted = submit(context)
    assert submitted.status_code == 201,submitted.text
    proposal_id = submitted.json()['proposal_id']
    viewed = preview(context,proposal_id)
    assert viewed.status_code == 200,viewed.text
    approved = approve(context,proposal_id)
    assert approved.status_code == 200,approved.text
    return proposal_id,approved.json()['grant_token']


def execute(context: Any, token: str, *, key: str | None = 'fixture-idempotency', action: Any = None) -> Any:
    headers = {**context['agent']}
    if key is not None:
        headers['Idempotency-Key'] = key
    return context['client'].post('/v1/execute',json={'action':action or context['action'],'grant_token':token},headers=headers)


def assert_deny(context: Any, response: Any, reason: str) -> None:
    """Every HTTP denial carries a persisted stable rule and exact policy hash."""
    body = response.json()
    assert not body['allowed'] and body['reason'] == reason,(response.status_code,body)
    assert response.status_code >= 400 and body['rule_id']
    assert body['policy_version'] == context['app'].state.gateway.policy.policy_version
    with Session(context['engine']) as session:
        receipt = session.get(Receipt,body['receipt_id'])
        assert receipt and not receipt.allowed and receipt.reason == reason
        assert receipt.rule_id == body['rule_id']


def assert_no_effect(context: Any, token: str | None = None) -> None:
    with Session(context['engine']) as session:
        assert session.get(Order,'order').refunded_paise == 0
        assert session.get(Order,'order').version == 1
        assert not session.get(Payment,'payment').in_flight
        assert session.scalar(select(func.count()).select_from(Refund)) == 0
        assert session.scalar(select(func.count()).select_from(Execution)) == 0
        if token:
            claims = jwt.decode(token,options={'verify_signature':False})
            assert session.get(UsedGrant,claims['jti']).status == 'ACTIVE'


def test_complete_workflow_and_retry(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id,token = authorized(ctx)
    with Session(ctx['engine']) as session:
        row = session.get(Proposal,proposal_id)
        assert row.status == 'APPROVED' and row.approved_resource_fingerprint
        assert session.get(UsedGrant,row.grant_id).status == 'ACTIVE'
    response = execute(ctx,token)
    assert response.status_code == 200,response.text
    assert response.json()['reason'] == 'EXECUTED'
    again = execute(ctx,token)
    assert again.json()['reason'] == 'IDEMPOTENT_RETRY'
    assert again.json()['refund_id'] == response.json()['refund_id']
    assert_deny(ctx,execute(ctx,token,key='new-key'),'GRANT_USED')
    with Session(ctx['engine']) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 1
        assert session.get(Order,'order').refunded_paise == 49900
        assert session.get(Order,'order').version == 2
        assert session.get(Proposal,proposal_id).status == 'EXECUTED'
        assert not session.get(Payment,'payment').in_flight
    assert response.headers['cache-control'] == 'no-store'


def test_preview_uses_live_trusted_fields(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    with Session(ctx['engine']) as session, session.begin():
        session.execute(update(Order).where(Order.id == 'order').values(refunded_paise=1000))
    result = preview(ctx,proposal_id)
    assert result.status_code == 200,result.text
    body = result.json()
    assert body['action_digest'] == digest(ctx['action'])
    assert body['preview'] == {'payment_id':'payment','order_id':'order','amount_paise':49900,'currency':'INR','destination':'original_payment','original_payment_destination':'original-payment','order_version':1,'remaining_refundable_paise':99000,'payment_created_at':None,'refund_deadline_at':None}
    assert 'IGNORE POLICY' not in result.text


@pytest.mark.parametrize('change,reason',[
    ({'tenant_id':'tenant-b'},'WRONG_TENANT'),({'actor_id':'human'},'ACTOR_MISMATCH'),
    ({'v':2},'UNSUPPORTED_SCHEMA_VERSION'),({'resource_ref':'different'},'RESOURCE_MISMATCH'),
    ({'resource_version':2},'STALE_RESOURCE'),
])
def test_submission_binding_denies(fixture_gateway: Any, change: Any, reason: str) -> None:
    action = {**fixture_gateway['action'],**change}
    assert_deny(fixture_gateway,submit(fixture_gateway,action),reason)
    with Session(fixture_gateway['engine']) as session:
        assert session.scalar(select(func.count()).select_from(Proposal)) == 0


@pytest.mark.parametrize('change,reason',[
    ({'payment_id':'missing'},'RESOURCE_NOT_FOUND'),({'amount_paise':100001},'REFUND_LIMIT_EXCEEDED'),
    ({'amount_paise':499.0},'INVALID_REQUEST'),({'amount_paise':'499'},'INVALID_REQUEST'),
    ({'destination':'other'},'INVALID_REQUEST'),({'unexpected':'field'},'INVALID_REQUEST'),
])
def test_strict_arguments_and_policy(fixture_gateway: Any, change: Any, reason: str) -> None:
    action = {**fixture_gateway['action'],'args':{**fixture_gateway['action']['args'],**change}}
    assert_deny(fixture_gateway,submit(fixture_gateway,action),reason)


def test_agent_cannot_preview_approve_or_read_legacy_routes(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    assert_deny(ctx,ctx['client'].get('/v1/proposals/'+proposal_id+'/preview',headers=ctx['agent']),'UNAUTHENTICATED')
    assert_deny(ctx,ctx['client'].post('/v1/proposals/'+proposal_id+'/approve',json={},headers=ctx['agent']),'UNAUTHENTICATED')
    for path in ['/api/agent/context','/api/state','/openapi.json','/v1/proposals']:
        assert_deny(ctx,ctx['client'].get(path,headers=ctx['agent']),'ENDPOINT_NOT_ALLOWED')


def test_operator_cannot_use_agent_endpoint(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    assert_deny(ctx,ctx['client'].post('/v1/proposals',json=ctx['action'],headers=ctx['operator']),'UNAUTHENTICATED')
    assert_deny(ctx,ctx['client'].post('/v1/execute',json={'action':ctx['action'],'grant_token':'x'},headers=ctx['operator']),'UNAUTHENTICATED')


@pytest.mark.parametrize('header_changes',[{'X-CSRF-Token':''},{'X-CSRF-Token':'wrong'},{'Origin':'https://attacker.invalid'},{'Sec-Fetch-Site':'cross-site'}])
def test_csrf_required_and_session_bound(fixture_gateway: Any, header_changes: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    preview(ctx,proposal_id)
    headers = {**ctx['approval'],**header_changes}
    assert_deny(ctx,ctx['client'].post('/v1/proposals/'+proposal_id+'/approve',json={},headers=headers),'CSRF_INVALID')
    assert_no_effect(ctx)
    with Session(ctx['engine']) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0


def test_approval_requires_this_session_preview(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    assert_deny(ctx,approve(ctx,proposal_id),'PREVIEW_REQUIRED')
    preview(ctx,proposal_id)
    with Session(ctx['engine']) as session, session.begin():
        token,csrf = provision_session(session,'human','gateway-kid',3600)
    result = ctx['client'].post('/v1/proposals/'+proposal_id+'/approve',json={},headers={'Cookie':'intentlock_session='+token,'X-CSRF-Token':csrf})
    assert_deny(ctx,result,'PREVIEW_REQUIRED')


def test_never_accept_client_digest(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    preview(ctx,proposal_id)
    result = ctx['client'].post('/v1/proposals/'+proposal_id+'/approve',json={'action_digest':digest(ctx['action'])},headers=ctx['approval'])
    assert_deny(ctx,result,'INVALID_REQUEST')
    assert approve(ctx,proposal_id).status_code == 200
    assert_deny(ctx,approve(ctx,proposal_id),'PROPOSAL_ALREADY_APPROVED')


@pytest.mark.parametrize('change,reason',[({'version':2},'STALE_RESOURCE'),({'refunded_paise':1000},'PREVIEW_STALE'),({'destination':'changed-payment'},'PREVIEW_STALE')])
def test_approval_refetches_and_rejects_stale_review(fixture_gateway: Any, change: Any, reason: str) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    preview(ctx,proposal_id)
    with Session(ctx['engine']) as session, session.begin():
        session.execute(update(Order).where(Order.id == 'order').values(**change))
    assert_deny(ctx,approve(ctx,proposal_id),reason)
    with Session(ctx['engine']) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0


@pytest.mark.parametrize('table,change,reason',[
    (Order,{'version':2},'STALE_RESOURCE'),(Order,{'destination':'changed-payment'},'STALE_RESOURCE'),
    (Order,{'refunded_paise':60000},'REFUND_LIMIT_EXCEEDED'),
    (Payment,{'destination_kind':'redirected'},'DESTINATION_NOT_ORIGINAL'),
    (Payment,{'in_flight':True},'REFUND_IN_FLIGHT'),(Order,{'currency':'USD'},'CURRENCY_MISMATCH'),
])
def test_execution_refetches_policy_and_rolls_back_consent(fixture_gateway: Any, table: Any, change: Any, reason: str) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    with Session(ctx['engine']) as session, session.begin():
        session.execute(update(table).values(**change))
    result = execute(ctx,token)
    assert_deny(ctx,result,reason)
    with Session(ctx['engine']) as session:
        claims = jwt.decode(token,options={'verify_signature':False})
        assert session.get(UsedGrant,claims['jti']).status == 'ACTIVE'
        assert session.scalar(select(func.count()).select_from(Refund)) == 0


def test_execution_idempotency_conflict_and_required_header(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    assert_deny(ctx,execute(ctx,token,key=None),'IDEMPOTENCY_KEY_REQUIRED')
    assert_deny(ctx,execute(ctx,token,key='bad key'),'INVALID_IDEMPOTENCY_KEY')
    assert execute(ctx,token).status_code == 200
    action = {**ctx['action'],'args':{**ctx['action']['args'],'amount_paise':1}}
    assert_deny(ctx,execute(ctx,token,action=action),'IDEMPOTENCY_CONFLICT')


def test_modified_action_denied_by_grant(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    action = {**ctx['action'],'args':{**ctx['action']['args'],'amount_paise':1}}
    assert_deny(ctx,execute(ctx,token,action=action),'ACTION_MISMATCH')
    assert_no_effect(ctx,token)


def test_orchestrator_exception_rolls_back_everything(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id,token = authorized(ctx)
    orchestrator = ctx['app'].state.gateway.orchestrator
    original = orchestrator.execute
    def fail_after_write(*args: Any, **kwargs: Any) -> str:
        original(*args,**kwargs)
        raise RuntimeError('fixture downstream failure')
    with patch.object(orchestrator,'execute',side_effect=fail_after_write):
        assert_deny(ctx,execute(ctx,token),'INTERNAL_ERROR')
    assert_no_effect(ctx,token)
    with Session(ctx['engine']) as session:
        assert session.get(Proposal,proposal_id).status == 'APPROVED'
    assert execute(ctx,token).status_code == 200


def test_audit_failure_rolls_back_effect(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    with patch.object(ctx['app'].state.gateway,'audit',side_effect=RuntimeError('fixture audit outage')):
        result = execute(ctx,token)
    assert result.status_code == 503 and result.json()['reason'] == 'AUDIT_UNAVAILABLE'
    assert_no_effect(ctx,token)


def test_policy_internal_error_denies_after_verification(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    with patch('app.core.policy.parse_action',side_effect=RuntimeError('fixture engine failure')):
        assert_deny(ctx,execute(ctx,token),'POLICY_ERROR')
    assert_no_effect(ctx,token)


def test_bad_signature_and_algorithm_confusion(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    header,payload,_ = token.split('.')
    forged = header+'.'+payload+'.'+base64.urlsafe_b64encode(bytes(64)).rstrip(b'=').decode()
    assert_deny(ctx,execute(ctx,forged),'BAD_SIGNATURE')
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","kid":"gateway-kid","typ":"JWT"}').rstrip(b'=').decode()
    assert_deny(ctx,execute(ctx,none_header+'.'+payload+'.'),'ALG_NOT_ALLOWED')
    assert_no_effect(ctx,token)


def test_expired_grant_denied(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    now = int(time.time())
    with patch('app.core.grants.time.time',return_value=now+331):
        assert_deny(ctx,execute(ctx,token),'EXPIRED')
    assert_no_effect(ctx,token)


def test_revoked_kid_denied(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    with Session(ctx['engine']) as session, session.begin():
        session.execute(update(KeyRegistry).values(active=False))
    assert_deny(ctx,execute(ctx,token),'UNKNOWN_KEY')
    assert_no_effect(ctx,token)


def test_policy_file_is_immutable_until_restart(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    version = ctx['app'].state.gateway.policy.policy_version
    ctx['policy_path'].write_bytes(ctx['policy_path'].read_bytes()+b'\n# actual deployment changed\n')
    assert submit(ctx).json()['policy_version'] == version
    restarted = create_app(ctx['config'])
    with TestClient(restarted) as client:
        assert client.app.state.gateway.policy.policy_version != version


def test_invalid_startup_policy_never_serves(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    ctx['policy_path'].write_text('default: allow\n')
    with pytest.raises(ValueError):
        with TestClient(create_app(ctx['config'])):
            raise AssertionError('invalid policy started')


def test_policy_change_after_approval_requires_new_proposal(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    ctx['policy_path'].write_bytes(ctx['policy_path'].read_bytes()+b'\n# next release\n')
    with TestClient(create_app(ctx['config'])) as client:
        result = client.post('/v1/execute',json={'action':ctx['action'],'grant_token':token},headers={**ctx['agent'],'Idempotency-Key':'fixture-new-deploy'})
        assert result.json()['reason'] == 'POLICY_CHANGED'
    assert_no_effect(ctx,token)


def test_concurrent_calls_create_at_most_one_refund(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: execute(ctx,token,key='fixture-race-'+str(i)),range(8)))
    assert sum(result.json()['allowed'] for result in results) == 1
    with Session(ctx['engine']) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 1
        assert session.get(Order,'order').refunded_paise == 49900


@pytest.mark.parametrize('table,values',[(AgentServiceKey,{'active':False}),(AgentServiceKey,{'expires_at':1})])
def test_agent_revocation_and_expiry(fixture_gateway: Any, table: Any, values: Any) -> None:
    with Session(fixture_gateway['engine']) as session, session.begin():
        session.execute(update(table).values(**values))
    assert_deny(fixture_gateway,submit(fixture_gateway),'UNAUTHENTICATED')


@pytest.mark.parametrize('table,values',[(OperatorSession,{'active':False}),(OperatorSession,{'expires_at':1}),(User,{'active':False})])
def test_operator_session_revocation_and_expiry(fixture_gateway: Any, table: Any, values: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    with Session(ctx['engine']) as session, session.begin():
        session.execute(update(table).values(**values))
    assert_deny(ctx,preview(ctx,proposal_id),'UNAUTHENTICATED')


def test_duplicate_json_unknown_fields_and_size(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    headers = {**ctx['agent'],'Content-Type':'application/json'}
    for raw in [b'{"v":1,"v":1}',b'{"args":{"amount_paise":499.0}}',b'NaN',b'\xff']:
        assert_deny(ctx,ctx['client'].post('/v1/proposals',content=raw,headers=headers),'INVALID_REQUEST')
    assert_deny(ctx,submit(ctx,{**ctx['action'],'extra':1}),'INVALID_REQUEST')
    assert_deny(ctx,ctx['client'].post('/v1/proposals',content=b'x'*65537,headers=headers),'REQUEST_TOO_LARGE')
    assert_deny(ctx,ctx['client'].post('/v1/proposals',content=b'{}',headers=ctx['agent']),'INVALID_CONTENT_TYPE')


def test_duplicate_authorization_headers_denied(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    result = ctx['client'].post('/v1/proposals',json=ctx['action'],headers=[('Authorization',ctx['agent']['Authorization']),('Authorization',ctx['agent']['Authorization'])])
    assert_deny(ctx,result,'AMBIGUOUS_HEADERS')


def test_missing_auth_and_unknown_proposal(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    assert_deny(ctx,ctx['client'].post('/v1/proposals',json=ctx['action']),'UNAUTHENTICATED')
    assert_deny(ctx,preview(ctx,'unknown'),'PROPOSAL_NOT_FOUND')
    assert_deny(ctx,ctx['client'].get('/v1/proposals/unknown/preview?tenant_id=other',headers=ctx['operator']),'INVALID_REQUEST')


def test_external_grant_without_operator_approval_is_not_executable(fixture_gateway: Any) -> None:
    from app.core.grants import GrantService, GrantSettings
    ctx = fixture_gateway
    grant = GrantService(ctx['engine'],GrantSettings(issuer='fixture-issuer',policy_version=ctx['app'].state.gateway.policy.policy_version,signing_kid='gateway-kid'))
    token = grant.issue_grant(digest(ctx['action']),'human','tenant-a',1)
    assert_deny(ctx,execute(ctx,token),'PROPOSAL_NOT_APPROVED')
    assert_no_effect(ctx,token)


def test_cookie_exchange_and_csrf_logout(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    token = ctx['operator']['Cookie'].split('=',1)[1]
    response = ctx['client'].post('/v1/session',json={'session_token':token,'csrf_token':ctx['approval']['X-CSRF-Token']})
    assert response.status_code == 200,response.text
    assert 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=strict' in response.headers['set-cookie'] and 'Path=/v1' in response.headers['set-cookie']
    assert token not in response.text
    assert_deny(ctx,ctx['client'].delete('/v1/session'),'CSRF_INVALID')
    logged_out = ctx['client'].delete('/v1/session',headers={'X-CSRF-Token':ctx['approval']['X-CSRF-Token']})
    assert logged_out.status_code == 200
    with Session(ctx['engine']) as session:
        assert not session.get(OperatorSession,ctx['session_id']).active
    assert_deny(ctx,ctx['client'].post('/v1/session',json={'session_token':token,'csrf_token':ctx['approval']['X-CSRF-Token']}),'UNAUTHENTICATED')


def test_agent_cannot_exchange_for_human_session(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    token = ctx['agent']['Authorization'].removeprefix('Bearer ')
    result = ctx['client'].post('/v1/session',json={'session_token':token,'csrf_token':token})
    assert_deny(ctx,result,'UNAUTHENTICATED')
    token = ctx['operator']['Cookie'].split('=',1)[1]
    result = ctx['client'].post('/v1/session',json={'session_token':token,'csrf_token':ctx['approval']['X-CSRF-Token']},headers=ctx['agent'])
    assert_deny(ctx,result,'UNAUTHENTICATED')


def test_session_credentials_stored_as_hashes_only(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    with Session(ctx['engine']) as session:
        row = session.get(OperatorSession,ctx['session_id'])
        values = json.dumps({column.name:getattr(row,column.name) for column in OperatorSession.__table__.columns})
        assert ctx['operator']['Cookie'].split('=',1)[1] not in values
        assert ctx['approval']['X-CSRF-Token'] not in values
        service = session.get(AgentServiceKey,'fixture-service')
        assert service.token_hash != ctx['agent']['Authorization'].removeprefix('Bearer ')


def test_other_tenant_cannot_preview_approve_or_execute(fixture_gateway: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from app.core.keys import public_key_text
    ctx = fixture_gateway
    proposal_id,token = authorized(ctx)
    other_key = Ed25519PrivateKey.generate()
    with Session(ctx['engine']) as session, session.begin():
        session.add(User(id='fixture-other-human',tenant_id='tenant-b',public_key=public_key_text(other_key.public_key()),active=True))
    register_public_key(ctx['engine'],'fixture-other-kid','fixture-other-human','tenant-b',other_key.public_key())
    with Session(ctx['engine']) as session, session.begin():
        cookie,csrf = provision_session(session,'fixture-other-human','fixture-other-kid',3600)
        agent = provision_agent(session,'fixture-other-service','tenant-b','other-actor',3600)
    headers = {'Cookie':'intentlock_session='+cookie,'X-CSRF-Token':csrf}
    assert_deny(ctx,ctx['client'].get('/v1/proposals/'+proposal_id+'/preview',headers=headers),'PROPOSAL_NOT_FOUND')
    assert_deny(ctx,ctx['client'].post('/v1/proposals/'+proposal_id+'/approve',json={},headers=headers),'PROPOSAL_NOT_FOUND')
    result = ctx['client'].post('/v1/execute',json={'action':ctx['action'],'grant_token':token},headers={'Authorization':'Bearer '+agent,'Idempotency-Key':'other-tenant'})
    assert_deny(ctx,result,'WRONG_TENANT')
    assert_no_effect(ctx,token)


def test_preview_rejects_cross_site_browser_request(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    result = ctx['client'].get('/v1/proposals/'+proposal_id+'/preview',headers={**ctx['operator'],'Sec-Fetch-Site':'cross-site'})
    assert_deny(ctx,result,'CSRF_INVALID')


def test_policy_read_scope_required_for_preview(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    document = yaml.safe_load(ctx['policy_path'].read_text())
    document['tenants']['tenant-a']['read_scopes'] = []
    ctx['policy_path'].write_text(yaml.safe_dump(document))
    with TestClient(create_app(ctx['config'])) as client:
        submitted = client.post('/v1/proposals',json=ctx['action'],headers=ctx['agent'])
        proposal_id = submitted.json()['proposal_id']
        result = client.get('/v1/proposals/'+proposal_id+'/preview',headers=ctx['operator'])
        assert result.json()['reason'] == 'READ_OUT_OF_SCOPE'


def test_execute_unknown_audience_is_denied(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    claims = jwt.decode(token,options={'verify_signature':False})
    claims['aud'] = 'different-service'
    changed = jwt.encode(claims,ctx['key'],algorithm='EdDSA',headers={'kid':'gateway-kid'})
    assert_deny(ctx,execute(ctx,changed),'WRONG_AUDIENCE')
    assert_no_effect(ctx,token)


def test_multiple_signing_secret_files(fixture_gateway: Any, tmp_path: Any, monkeypatch: Any) -> None:
    ctx = fixture_gateway
    path = tmp_path/'fixture-protected.pem'
    path.write_bytes(ctx['key'].private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    path.chmod(0o600)
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PEM')
    monkeypatch.setenv('GRANT_KEY_FILE_MAP',json.dumps({'gateway-kid':str(path)}))
    _,token = authorized(ctx)
    assert execute(ctx,token).status_code == 200


def test_duplicate_cookie_and_csrf_headers_deny(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    cookie = ctx['operator']['Cookie']
    result = ctx['client'].get('/v1/proposals/'+proposal_id+'/preview',headers={'Cookie':cookie+'; '+cookie})
    assert_deny(ctx,result,'UNAUTHENTICATED')
    result = ctx['client'].post('/v1/proposals/'+proposal_id+'/approve',json={},headers=[('Cookie',cookie),('X-CSRF-Token',ctx['approval']['X-CSRF-Token']),('X-CSRF-Token',ctx['approval']['X-CSRF-Token'])])
    assert_deny(ctx,result,'AMBIGUOUS_HEADERS')


def test_second_service_cannot_redeem_first_services_approval(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    with Session(ctx['engine']) as session, session.begin():
        other = provision_agent(session,'fixture-secondary','tenant-a','agent-actor',3600)
    response = ctx['client'].post('/v1/execute',json={'action':ctx['action'],'grant_token':token},headers={'Authorization':'Bearer '+other,'Idempotency-Key':'other-service'})
    assert_deny(ctx,response,'PROPOSAL_NOT_APPROVED')
    assert_no_effect(ctx,token)


def test_simultaneous_independent_approvals_share_one_payment(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,first = authorized(ctx)
    _,second = authorized(ctx)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda pair:execute(ctx,pair[1],key=pair[0]),[('first-approval',first),('second-approval',second)]))
    assert sum(result.json()['allowed'] for result in outcomes) == 1
    with Session(ctx['engine']) as session:
        assert session.scalar(select(func.count()).select_from(Refund)) == 1


def test_duplicate_approval_cannot_mint_two_active_grants(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    preview(ctx,proposal_id)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _:approve(ctx,proposal_id),range(4)))
    assert sum(response.json()['allowed'] for response in responses) == 1
    with Session(ctx['engine']) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant).where(UsedGrant.status == 'ACTIVE')) == 1


def test_missing_signing_secret_cannot_approve(fixture_gateway: Any, monkeypatch: Any) -> None:
    ctx = fixture_gateway
    proposal_id = submit(ctx).json()['proposal_id']
    preview(ctx,proposal_id)
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PEM')
    assert_deny(ctx,approve(ctx,proposal_id),'UNKNOWN_KEY')
    with Session(ctx['engine']) as session:
        assert session.get(Proposal,proposal_id).status == 'PENDING'
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0


def test_invalid_resource_metadata_denies(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    with Session(ctx['engine']) as session, session.begin():
        session.execute(update(Order).values(destination=''))
    assert_deny(ctx,submit(ctx),'INVALID_RESOURCE')


def test_original_payment_reservation_is_an_atomic_guard(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    gateway = ctx['app'].state.gateway
    original = gateway.orchestrator.execute
    def reserve_before_orchestration(session: Any, *args: Any) -> str:
        session.execute(update(Payment).where(Payment.id == 'payment').values(in_flight=True))
        return original(session,*args)
    with patch.object(gateway.orchestrator,'execute',side_effect=reserve_before_orchestration):
        assert_deny(ctx,execute(ctx,token),'REFUND_IN_FLIGHT')
    assert_no_effect(ctx,token)


def test_order_compare_and_swap_catches_version_race(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    orchestrator = ctx['app'].state.gateway.orchestrator
    original = orchestrator.execute
    def change_version(session: Any, *args: Any) -> str:
        session.execute(update(Order).where(Order.id == 'order').values(version=2))
        return original(session,*args)
    with patch.object(orchestrator,'execute',side_effect=change_version):
        assert_deny(ctx,execute(ctx,token),'STALE_RESOURCE')
    assert_no_effect(ctx,token)


def test_retry_after_policy_restart_returns_only_stored_effect(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    _,token = authorized(ctx)
    first = execute(ctx,token).json()
    ctx['policy_path'].write_bytes(ctx['policy_path'].read_bytes()+b'\n# next deployed policy\n')
    with TestClient(create_app(ctx['config'])) as client:
        retried = client.post('/v1/execute',json={'action':ctx['action'],'grant_token':token},headers={**ctx['agent'],'Idempotency-Key':'fixture-idempotency'}).json()
        assert retried['reason'] == 'IDEMPOTENT_RETRY' and retried['refund_id'] == first['refund_id']
        assert retried['execution_policy_version'] == first['policy_version']
        assert retried['policy_version'] == client.app.state.gateway.policy.policy_version
        with Session(ctx['engine']) as session:
            assert session.get(Receipt,retried['receipt_id']).policy_version == retried['policy_version']
            assert session.scalar(select(func.count()).select_from(Refund)) == 1


def test_logout_body_remains_strict(fixture_gateway: Any) -> None:
    ctx = fixture_gateway
    response = ctx['client'].request('DELETE','/v1/session',json=[],headers=ctx['approval'])
    assert_deny(ctx,response,'INVALID_REQUEST')
    with Session(ctx['engine']) as session:
        assert session.get(OperatorSession,ctx['session_id']).active


def test_https_session_cookie_is_secure(fixture_gateway: Any) -> None:
    from dataclasses import replace
    ctx = fixture_gateway
    config = replace(ctx['config'],origin='https://gateway.example')
    token = ctx['operator']['Cookie'].split('=',1)[1]
    with TestClient(create_app(config),base_url='https://gateway.example') as client:
        response = client.post('/v1/session',json={'session_token':token,'csrf_token':ctx['approval']['X-CSRF-Token']})
        assert response.status_code == 200
        cookie = response.headers['set-cookie']
        assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=strict' in cookie
