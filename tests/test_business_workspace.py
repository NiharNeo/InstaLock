"""Fixture-only business isolation and OIDC security checks; no live provider calls."""
import json
import time
from typing import Any
import httpx
import jwt
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.auth.oidc import bind_identity,validate_id_token
from app.core.errors import GatewayDenied
from intentlock.db import SSOIdentity,SSOAttempt,Receipt,IntegrationRequest,Order,Payment
from test_gateway_v1 import fixture_gateway
from test_policy import fixture_policy_document,fixture_v1_action


@pytest.fixture
def fixture_identity(tmp_path: Any,monkeypatch: Any) -> dict[str,Any]:
    """Cryptographic and identity-provider fixtures; never used by application code."""
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='fixture-idp',alg='RS256',use='sig')
    claims={'iss':'https://fixture.identity','aud':'fixture-client','sub':'fixture-subject','nonce':'fixture-nonce','email':'human@fixture.test','email_verified':True,'iat':int(time.time()),'exp':int(time.time())+300}
    path=tmp_path/'fixture-dispatch.key';path.write_bytes(Fernet.generate_key());path.chmod(0o600)
    monkeypatch.setenv('DISPATCH_KEY_FILE',str(path));monkeypatch.setenv('INTAKE_RATE_SECRET','fixture-intake-secret-'*3)
    return {'key':key,'keys':{'keys':[jwk]},'claims':claims}


def signed(fixture: dict[str,Any],changes: dict[str,Any] | None=None) -> str:
    """Sign only synthetic fixture identity claims."""
    return jwt.encode({**fixture['claims'],**(changes or {})},fixture['key'],algorithm='RS256',headers={'kid':'fixture-idp'})


@pytest.mark.parametrize('changes',[{'iss':'https://evil.fixture'},{'aud':'other-client'},{'exp':0},{'iat':int(time.time())+600},{'nonce':'other'},{'email_verified':False},{'email_verified':'true'},{'sub':''},{'azp':'other'},{'aud':['fixture-client','other']},{'email':[] }])
def test_invalid_identity_claims(fixture_identity: Any,changes: dict[str,Any]) -> None:
    """An ID token cannot cross issuer, audience, time, nonce or verified-identity boundaries."""
    f=fixture_identity
    with pytest.raises((ValueError,jwt.PyJWTError)):
        validate_id_token(signed(f,changes),f['keys'],'https://fixture.identity','fixture-client','fixture-nonce')


@pytest.mark.parametrize('algorithm',['none','HS256'])
def test_identity_algorithm_confusion(fixture_identity: Any,algorithm: str) -> None:
    """Unsecured and symmetric identity tokens never reach invitation binding."""
    f=fixture_identity
    token=jwt.encode(f['claims'],'' if algorithm=='none' else 'fixture-confusion-key-long-enough-for-hmac',algorithm=algorithm,headers={'kid':'fixture-idp'})
    with pytest.raises(ValueError):validate_id_token(token,f['keys'],'https://fixture.identity','fixture-client','fixture-nonce')


def test_identity_signature_and_key(fixture_identity: Any) -> None:
    """Forgery and duplicate/unknown keys fail closed."""
    f=fixture_identity
    token=signed(f)
    assert validate_id_token(token,f['keys'],'https://fixture.identity','fixture-client','fixture-nonce')['sub']=='fixture-subject'
    with pytest.raises(ValueError):validate_id_token(token,{'keys':[]},'https://fixture.identity','fixture-client','fixture-nonce')
    with pytest.raises(ValueError):validate_id_token(token,{'keys':f['keys']['keys']*2},'https://fixture.identity','fixture-client','fixture-nonce')
    other=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    forged=jwt.encode(f['claims'],other,algorithm='RS256',headers={'kid':'fixture-idp'})
    with pytest.raises(jwt.InvalidSignatureError):validate_id_token(forged,f['keys'],'https://fixture.identity','fixture-client','fixture-nonce')


def test_invitation_binding(fixture_gateway: Any,fixture_identity: Any) -> None:
    """Verified email alone grants nothing; invited subject is pinned and revocation enforced."""
    c=fixture_gateway;claims=fixture_identity['claims']
    with Session(c['engine']) as session,session.begin():
        with pytest.raises(GatewayDenied):bind_identity(session,claims,'https://fixture.identity')
        session.add(SSOIdentity(email=claims['email'],issuer=claims['iss'],user_id='human',signing_kid='gateway-kid',subject=None,active=True));session.flush()
        token,csrf=bind_identity(session,claims,claims['iss'])
        assert token and csrf and session.get(SSOIdentity,claims['email']).subject==claims['sub']
        with pytest.raises(GatewayDenied):bind_identity(session,{**claims,'sub':'other-subject'},claims['iss'])
        with pytest.raises(GatewayDenied):bind_identity(session,claims,'https://different.fixture')
        session.get(SSOIdentity,claims['email']).active=False
        with pytest.raises(GatewayDenied):bind_identity(session,claims,claims['iss'])


def test_business_isolation_and_setup_csrf(fixture_gateway: Any) -> None:
    """Payment lists and setup requests use session tenant; services cannot connect accounts."""
    c=fixture_gateway
    with Session(c['engine']) as s,s.begin():
        s.add(Order(id='other-order',tenant_id='other-tenant',paid_paise=100,refunded_paise=0,currency='INR',destination='original_payment',version=1));s.flush()
        s.add(Payment(id='other-payment',tenant_id='other-tenant',order_id='other-order',destination_kind='original_payment',in_flight=False))
    response=c['client'].get('/v1/business',headers=c['operator']);assert response.status_code==200,response.text
    assert [p['id'] for p in response.json()['payments']]==['payment']
    assert response.json()['connection']['status']=='NOT_CONFIGURED'
    assert c['client'].get('/v1/business',headers=c['agent']).status_code==401
    assert c['client'].get('/v1/business?tenant_id=other-tenant',headers=c['operator']).status_code==400
    path='/v1/integrations/razorpay/request'
    assert c['client'].post(path,json={},headers=c['operator']).status_code==403
    assert c['client'].post(path,json={},headers=c['agent']).status_code==401
    assert c['client'].post(path,json={'tenant_id':'other-tenant'},headers=c['approval']).status_code==400
    for _ in range(2):assert c['client'].post(path,json={},headers=c['approval']).status_code==202
    with Session(c['engine']) as s:
        rows=s.scalars(select(IntegrationRequest)).all();assert len(rows)==1 and rows[0].tenant_id=='tenant-a' and rows[0].status=='AWAITING_CONFIGURATION'


def test_sso_disabled_without_config(fixture_gateway: Any,monkeypatch: Any) -> None:
    """Unconfigured SSO is visibly unavailable and never creates a session."""
    monkeypatch.delenv('OIDC_ISSUER',raising=False)
    c=fixture_gateway
    assert not c['client'].get('/v1/auth/providers').json()['sso_enabled']
    response=c['client'].get('/v1/auth/start');assert response.status_code==503
    assert response.json()['reason']=='SSO_NOT_CONFIGURED'


def test_oidc_browser_binding_replay_and_real_login(fixture_gateway: Any,fixture_identity: Any,monkeypatch: Any) -> None:
    """Full fixture code flow enforces browser state, one-use state, PKCE and invitation."""
    from urllib.parse import parse_qs,urlsplit
    c=fixture_gateway;f=fixture_identity
    for k,v in {'OIDC_ISSUER':'https://fixture.identity','OIDC_CLIENT_ID':'fixture-client','OIDC_CLIENT_SECRET':'fixture-client-secret'}.items():monkeypatch.setenv(k,v)
    with Session(c['engine']) as s,s.begin():s.add(SSOIdentity(email=f['claims']['email'],issuer=f['claims']['iss'],user_id='human',signing_kid='gateway-kid',subject=None,active=True))
    original=httpx.Client
    def upstream(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith('/openid-configuration'):
            return httpx.Response(200,json={'issuer':'https://fixture.identity','authorization_endpoint':'https://fixture.identity/authorize','token_endpoint':'https://fixture.identity/token','jwks_uri':'https://fixture.identity/keys','claims_parameter_supported':True})
        if request.url.path=='/keys':return httpx.Response(200,json=f['keys'])
        assert request.url.path=='/token'
        with Session(c['engine']) as s:row=s.scalars(select(SSOAttempt)).first();nonce=row.nonce
        form=parse_qs(request.content.decode());assert form['code_verifier'] and form['redirect_uri']==['http://localhost:8080/v1/auth/callback']
        return httpx.Response(200,json={'id_token':signed(f,{'nonce':nonce})})
    monkeypatch.setattr('app.auth.oidc.httpx.Client',lambda **kwargs:original(transport=httpx.MockTransport(upstream),**kwargs))
    start=c['client'].get('/v1/auth/start',follow_redirects=False);assert start.status_code==302,start.text
    args=parse_qs(urlsplit(start.headers['location']).query);assert args['code_challenge_method']==['S256'] and args['prompt']==['select_account']
    state=args['state'][0]
    callback='/v1/auth/callback?state='+state+'&code=fixture-code'
    browser=c['client'].cookies.get('intentlock_oidc')
    # Wrong browser does not consume the valid attempt.
    assert c['client'].get(callback,headers={'Cookie':'intentlock_oidc=wrong'},follow_redirects=False).status_code==403
    response=c['client'].get(callback,headers={'Cookie':'intentlock_oidc='+browser},follow_redirects=False);assert response.status_code==303,response.text
    assert 'HttpOnly' in response.headers['set-cookie'] and 'intentlock_session=' in response.headers['set-cookie']
    assert c['client'].get('/v1/console').status_code==200
    assert c['client'].get(callback,follow_redirects=False).status_code==403
    with Session(c['engine']) as s:
        row=s.scalars(select(SSOAttempt)).first();assert row.used and not row.verifier_ciphertext
        for receipt in s.scalars(select(Receipt)):
            assert 'fixture-code' not in str(receipt.__dict__) and 'fixture-client-secret' not in str(receipt.__dict__)


def test_executor_connection_status_tenant_and_secret_boundary(fixture_gateway: Any) -> None:
    """Executor metadata is authenticated and tenant-bound; secrets never enter status JSON."""
    from fastapi.testclient import TestClient
    from app.executor.main import create_app
    from app.executor.config import ExecutorSettings
    c=fixture_gateway
    settings=ExecutorSettings(c['config'].database_url,c['policy_path'],'fixture-issuer','tenant-a','acc_fixture','rzp_test_fixture','fixture-secret','w'*32,'i'*32)
    with TestClient(create_app(settings)) as client:
        path='/internal/integrations/status'
        assert client.post(path,json={'tenant_id':'tenant-a'}).status_code==401
        headers={'Authorization':'Bearer '+settings.internal_token}
        assert client.post(path,json={'tenant_id':'other'},headers=headers).json()['reason']=='WRONG_TENANT'
        result=client.post(path,json={'tenant_id':'tenant-a'},headers=headers)
        assert result.status_code==200
        assert result.json()=={'provider':'razorpay','status':'CONFIGURED','mode':'test','account_id':'acc_fixture','tenant_id':'tenant-a'}
        assert settings.key_secret not in result.text and settings.webhook_secret not in result.text


@pytest.mark.parametrize('change',[{'exp':int(time.time())+300.5},{'iat':str(int(time.time()))},{'iat':True}])
def test_identity_timestamps_strict(fixture_identity: Any,change: dict[str,Any]) -> None:
    """Identity timestamps are actual integers rather than coerced strings, booleans or floats."""
    f=fixture_identity
    with pytest.raises((ValueError,jwt.PyJWTError)):
        validate_id_token(signed(f,change),f['keys'],'https://fixture.identity','fixture-client','fixture-nonce')


def test_parallel_console_and_business_reads(fixture_gateway: Any) -> None:
    """Parallel initial loads and tab polling must not deadlock their audit writes."""
    from concurrent.futures import ThreadPoolExecutor
    c=fixture_gateway
    def read(index: int) -> int:
        return c['client'].get('/v1/console' if index%2 else '/v1/business',headers=c['operator']).status_code
    with ThreadPoolExecutor(max_workers=16) as pool:
        statuses=list(pool.map(read,range(64)))
    assert statuses==[200]*64,statuses
    from app.core.receipts import verify_chain
    with Session(c['engine']) as session:assert verify_chain(session,'tenant-a')['valid']


def test_identity_protocol_booleans_do_not_relax_actions() -> None:
    """Real discovery boolean flags work; ambiguous JSON and action booleans still fail."""
    from app.auth.oidc import parse_identity_json
    from app.core.canonical import _load_json
    assert parse_identity_json(b'{"claims_parameter_supported":true,"other":[false,null]}')['claims_parameter_supported'] is True
    for raw in [b'{"flag":true,"flag":false}',b'{"number":1.0}',b'{"number":NaN}']:
        with pytest.raises(ValueError):parse_identity_json(raw)
    with pytest.raises(ValueError):_load_json(b'{"amount_paise":true}')
