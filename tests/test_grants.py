"""JWT misuse regression tests; all identities/actions/keys are test fixtures."""
import base64
import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.canonical import digest
from app.core.grants import (
    AUDIENCE, CLOCK_SKEW_SECONDS, DenyReason, GrantClaims, GrantIssueError,
    GrantService, GrantSettings, GrantVerification, issue_grant, verify_grant,
)
from app.core.keys import public_key_text, register_public_key, revoke_key
from intentlock.db import KeyRegistry, Order, Receipt, UsedGrant, User


@pytest.fixture
def fixture_jwt(fixture_context: Any, monkeypatch: Any) -> Any:
    """A provisioned real-schema human/key pair and an environment-only signer."""
    cfg, engine, key, _ = fixture_context
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM', pem)
    monkeypatch.delenv('GRANT_PRIVATE_KEY_FILE', raising=False)
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PASSWORD', raising=False)
    monkeypatch.setenv('GRANT_ISSUER', 'fixture-issuer')
    monkeypatch.setenv('GRANT_SIGNING_KID', 'fixture-kid')
    monkeypatch.setenv('POLICY_VERSION', cfg.policy_version)
    monkeypatch.setenv('DATABASE_URL', cfg.database_url)
    register_public_key(engine, 'fixture-kid', 'human', cfg.agent_tenant, key.public_key())
    action = {'v':1,'tool':'refund.create','args':{'payment_id':'fixture-payment','amount_paise':499,'currency':'INR','destination':'original_payment'},'tenant_id':cfg.agent_tenant,'actor_id':'human','resource_ref':'order','resource_version':1}
    action_digest = digest(action)
    service = GrantService(engine, GrantSettings(issuer='fixture-issuer', policy_version=cfg.policy_version, signing_kid='fixture-kid'))
    return service, engine, key, action_digest


def make_token(context: Any) -> str:
    """Issue a fixture token through the trusted service."""
    return context[0].issue_grant(context[3], 'human', 'tenant-a', 1)


def verify(context: Any, token: str, **changes: Any) -> GrantVerification:
    """Verify against trusted fixture context, optionally changing one binding."""
    args = {'expected_digest':context[3],'tenant_id':'tenant-a','current_resource_version':1}
    args.update(changes)
    return context[0].verify_grant(token, **args)


def raw_claims(token: str) -> dict[str, Any]:
    """Read fixture claims without trust, for constructing adversarial tokens."""
    return jwt.decode(token, options={'verify_signature':False})


def assert_deny(context: Any, result: GrantVerification, reason: DenyReason, token: str | None = None) -> None:
    """Every denial has a committed receipt, and leaves its grant unconsumed."""
    assert not result.allowed and result.reason is reason and result.claims is None
    with Session(context[1]) as session:
        audit = session.get(Receipt,result.receipt_id)
        assert audit and not audit.allowed and audit.reason == reason.value
        assert audit.rule_id and audit.policy_version
        if token:
            row = session.get(UsedGrant,raw_claims(token)['jti'])
            assert row.status == 'ACTIVE'


def resign(context: Any, token: str, **changes: Any) -> str:
    """Construct a correctly signed but unauthorized alteration for testing."""
    claims = raw_claims(token)
    claims.update(changes)
    return jwt.encode(claims,context[2],algorithm='EdDSA',headers={'kid':'fixture-kid'})


def test_issue_exact_claims_and_active_row(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    header = jwt.get_unverified_header(token)
    assert header == {'alg':'EdDSA','kid':'fixture-kid','typ':'JWT'}
    payload = jwt.decode(token,fixture_jwt[2].public_key(),algorithms=['EdDSA'],issuer='fixture-issuer',audience=AUDIENCE)
    assert set(payload) == {'iss','aud','sub','tid','jti','iat','exp','act_digest','res_ver','max_uses'}
    assert payload['sub'] == 'human' and payload['tid'] == 'tenant-a'
    assert UUID(payload['jti']).version == 4
    assert payload['exp'] - payload['iat'] == 300 and payload['max_uses'] == 1
    assert payload['res_ver'] == 1 and payload['act_digest'] == fixture_jwt[3]
    with Session(fixture_jwt[1]) as session:
        row = session.get(UsedGrant,payload['jti'])
        assert row.status == 'ACTIVE' and row.kid == 'fixture-kid'
        assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert row.payload == payload
        assert session.scalar(select(Receipt).where(Receipt.reason == 'GRANT_ISSUED')).allowed


def test_verified_grant_is_single_use(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    first = verify(fixture_jwt,token)
    assert first.allowed and first.reason is None and isinstance(first.claims,GrantClaims)
    second = verify(fixture_jwt,token)
    assert_deny(fixture_jwt,second,DenyReason.GRANT_USED)
    with Session(fixture_jwt[1]) as session:
        assert session.get(UsedGrant,first.claims.jti).status == 'USED'
        assert session.get(Receipt,first.receipt_id).reason == 'GRANT_CONSUMED'


def test_forged_signature(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    header, payload, _ = token.split('.')
    forged = header + '.' + payload + '.' + base64.urlsafe_b64encode(bytes(64)).rstrip(b'=').decode()
    assert_deny(fixture_jwt,verify(fixture_jwt,forged),DenyReason.BAD_SIGNATURE,token)


@pytest.mark.parametrize('alg',['none','HS256','RS256','Ed25519'])
def test_algorithm_pinned(fixture_jwt: Any, alg: str) -> None:
    token = make_token(fixture_jwt)
    _, payload, _ = token.split('.')
    header = base64.urlsafe_b64encode(json.dumps({'alg':alg,'kid':'fixture-kid','typ':'JWT'}).encode()).rstrip(b'=')
    signing_input = header + b'.' + payload.encode()
    # A genuine HMAC using the Ed25519 public bytes reproduces alg confusion.
    signature = hmac.new(fixture_jwt[2].public_key().public_bytes_raw(),signing_input,hashlib.sha256).digest()
    attack = signing_input.decode() + '.' + base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    if alg == 'none':
        attack = signing_input.decode() + '.'
    assert_deny(fixture_jwt,verify(fixture_jwt,attack),DenyReason.ALG_NOT_ALLOWED,token)


@pytest.mark.parametrize('field,value',[('sub','attacker'),('tid','tenant-b'),('res_ver',2),('act_digest','sha256:'+'0'*64),('exp',9007199254740000)])
def test_tampered_claims_fail_signature(fixture_jwt: Any, field: str, value: Any) -> None:
    token = make_token(fixture_jwt)
    header, _, signature = token.split('.')
    claims = raw_claims(token)
    claims[field] = value
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    attack = header + '.' + payload + '.' + signature
    assert_deny(fixture_jwt,verify(fixture_jwt,attack),DenyReason.BAD_SIGNATURE,token)


@pytest.mark.parametrize('change,reason',[
    ({'tenant_id':'tenant-b'},DenyReason.WRONG_TENANT),
    ({'expected_digest':'sha256:'+'0'*64},DenyReason.ACTION_MISMATCH),
    ({'expected_digest':'not-a-digest'},DenyReason.ACTION_MISMATCH),
    ({'current_resource_version':2},DenyReason.STALE_RESOURCE),
    ({'current_resource_version':True},DenyReason.STALE_RESOURCE),
    ({'current_resource_version':1.0},DenyReason.STALE_RESOURCE),
])
def test_trusted_context_bindings(fixture_jwt: Any, change: Any, reason: DenyReason) -> None:
    token = make_token(fixture_jwt)
    assert_deny(fixture_jwt,verify(fixture_jwt,token,**change),reason,token)


@pytest.mark.parametrize('claims,reason',[
    ({'aud':'another-service'},DenyReason.WRONG_AUDIENCE),
    ({'iss':'another-issuer'},DenyReason.BAD_SIGNATURE),
    ({'tid':'tenant-b'},DenyReason.WRONG_TENANT),
    ({'sub':'different-human'},DenyReason.BAD_SIGNATURE),
    ({'max_uses':2},DenyReason.BAD_SIGNATURE),
    ({'max_uses':True},DenyReason.BAD_SIGNATURE),
    ({'res_ver':1.0},DenyReason.BAD_SIGNATURE),
    ({'jti':'not-a-uuid'},DenyReason.BAD_SIGNATURE),
    ({'iat':1},DenyReason.BAD_SIGNATURE),
    ({'nbf':1},DenyReason.BAD_SIGNATURE),
    ({'aud':['intentlock-gateway']},DenyReason.BAD_SIGNATURE),
])
def test_signed_invalid_claims(fixture_jwt: Any, claims: Any, reason: DenyReason) -> None:
    token = make_token(fixture_jwt)
    attack = resign(fixture_jwt,token,**claims)
    assert_deny(fixture_jwt,verify(fixture_jwt,attack),reason,token)


@pytest.mark.parametrize('offset,allowed',[(299,True),(300,True),(329,True),(330,False),(331,False)])
def test_expiry_exact_30_second_skew(fixture_jwt: Any, offset: int, allowed: bool) -> None:
    issued_at = 1800000000
    with patch('app.core.grants.time.time',return_value=issued_at):
        token = make_token(fixture_jwt)
    with patch('app.core.grants.time.time',return_value=issued_at+offset):
        result = verify(fixture_jwt,token)
    if allowed:
        assert result.allowed
    else:
        assert_deny(fixture_jwt,result,DenyReason.EXPIRED,token)


@pytest.mark.parametrize('future_seconds,allowed',[(30,True),(31,False)])
def test_future_issuance_skew(fixture_jwt: Any, future_seconds: int, allowed: bool) -> None:
    with patch('app.core.grants.time.time',return_value=1800000000):
        token = make_token(fixture_jwt)
    with patch('app.core.grants.time.time',return_value=1800000000-future_seconds):
        result = verify(fixture_jwt,token)
    assert result.allowed is allowed
    if not allowed:
        assert_deny(fixture_jwt,result,DenyReason.EXPIRED,token)


def test_unknown_key_and_revocation(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    unknown = jwt.encode(raw_claims(token),fixture_jwt[2],algorithm='EdDSA',headers={'kid':'absent'})
    assert_deny(fixture_jwt,verify(fixture_jwt,unknown),DenyReason.UNKNOWN_KEY,token)
    revoke_key(fixture_jwt[1],'fixture-kid')
    assert_deny(fixture_jwt,verify(fixture_jwt,token),DenyReason.UNKNOWN_KEY,token)


def test_rotation_keeps_old_kid_until_revoked(fixture_jwt: Any, monkeypatch: Any) -> None:
    service, engine, _, action_digest = fixture_jwt
    old_token = make_token(fixture_jwt)
    new_key = Ed25519PrivateKey.generate()
    register_public_key(engine,'new-kid','human','tenant-a',new_key.public_key())
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM',new_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    new_service = GrantService(engine,GrantSettings(issuer='fixture-issuer',policy_version='policy-1',signing_kid='new-kid'))
    new_token = new_service.issue_grant(action_digest,'human','tenant-a',1)
    assert service.verify_grant(old_token,action_digest,'tenant-a',1).allowed
    revoke_key(engine,'fixture-kid')
    assert new_service.verify_grant(new_token,action_digest,'tenant-a',1).allowed
    assert verify(fixture_jwt,old_token).reason is DenyReason.UNKNOWN_KEY


def test_signature_valid_but_no_issued_row(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    attack = resign(fixture_jwt,token,jti=str(uuid4()))
    assert_deny(fixture_jwt,verify(fixture_jwt,attack),DenyReason.GRANT_USED,token)


def test_changed_signed_claims_cannot_reuse_active_row(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    attack = resign(fixture_jwt,token,res_ver=2)
    result = verify(fixture_jwt,attack,current_resource_version=2)
    assert_deny(fixture_jwt,result,DenyReason.BAD_SIGNATURE,token)


def test_verify_never_loads_private_key(fixture_jwt: Any, monkeypatch: Any) -> None:
    token = make_token(fixture_jwt)
    for variable in ('GRANT_PRIVATE_KEY_PEM','GRANT_PRIVATE_KEY_FILE','GRANT_PRIVATE_KEY_PASSWORD','GRANT_SIGNING_KID'):
        monkeypatch.delenv(variable,raising=False)
    with patch('app.core.grants.load_private_key',side_effect=AssertionError('verifier accessed private key')):
        assert verify_grant(token,fixture_jwt[3],'tenant-a',1).allowed


def test_function_wrapper_issuance(fixture_jwt: Any) -> None:
    token = issue_grant(fixture_jwt[3],'human','tenant-a',1)
    assert verify_grant(token,fixture_jwt[3],'tenant-a',1).allowed


@pytest.mark.parametrize('value',[0,1.0,True,'1',9007199254740992])
def test_issue_invalid_versions(fixture_jwt: Any, value: Any) -> None:
    with pytest.raises(GrantIssueError):
        fixture_jwt[0].issue_grant(fixture_jwt[3],'human','tenant-a',value)
    with Session(fixture_jwt[1]) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0
        assert session.scalar(select(func.count()).select_from(Receipt)) == 1


def test_issue_wrong_operator_or_key(fixture_jwt: Any, monkeypatch: Any) -> None:
    with pytest.raises(GrantIssueError):
        fixture_jwt[0].issue_grant(fixture_jwt[3],'not-human','tenant-a',1)
    other_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM',other_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode())
    with pytest.raises(GrantIssueError,match='UNKNOWN_KEY'):
        make_token(fixture_jwt)
    with Session(fixture_jwt[1]) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0


def test_audit_failure_does_not_consume(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with patch.object(fixture_jwt[0],'_audit',side_effect=RuntimeError('fixture audit outage')):
        result = verify(fixture_jwt,token)
    assert not result.allowed and result.reason is DenyReason.AUDIT_UNAVAILABLE
    with Session(fixture_jwt[1]) as session:
        assert session.get(UsedGrant,raw_claims(token)['jti']).status == 'ACTIVE'


def test_issue_audit_failure_does_not_publish(fixture_jwt: Any) -> None:
    with patch.object(fixture_jwt[0],'_audit',side_effect=RuntimeError('fixture audit outage')):
        with pytest.raises(GrantIssueError,match='AUDIT_UNAVAILABLE'):
            make_token(fixture_jwt)
    with Session(fixture_jwt[1]) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0


def test_caller_transaction_consumption_and_effect_rollback(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with pytest.raises(RuntimeError):
        with Session(fixture_jwt[1]) as session, session.begin():
            result = fixture_jwt[0].verify_grant(token,fixture_jwt[3],'tenant-a',1,session=session)
            assert result.allowed
            session.execute(update(Order).where(Order.id == 'order').values(refunded_paise=499))
            raise RuntimeError('fixture downstream effect failed')
    with Session(fixture_jwt[1]) as session:
        assert session.get(UsedGrant,raw_claims(token)['jti']).status == 'ACTIVE'
        assert session.get(Order,'order').refunded_paise == 0
        assert session.get(Receipt,result.receipt_id) is None
    assert verify(fixture_jwt,token).allowed


def test_caller_transaction_commits_consumption_with_effect(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with Session(fixture_jwt[1]) as session, session.begin():
        result = fixture_jwt[0].verify_grant(token,fixture_jwt[3],'tenant-a',1,session=session)
        assert result.allowed
        session.execute(update(Order).where(Order.id == 'order').values(refunded_paise=499))
    with Session(fixture_jwt[1]) as session:
        assert session.get(UsedGrant,raw_claims(token)['jti']).status == 'USED'
        assert session.get(Order,'order').refunded_paise == 499
        assert session.get(Receipt,result.receipt_id).allowed


def test_concurrent_replay_at_most_one_allow(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: verify(fixture_jwt,token),range(8)))
    assert sum(result.allowed for result in results) == 1
    assert all(result.reason in {None,DenyReason.GRANT_USED,DenyReason.INTERNAL_ERROR} for result in results)
    with Session(fixture_jwt[1]) as session:
        assert session.scalar(select(func.count()).select_from(Receipt)) == 9


@pytest.mark.parametrize('token',['','x.y','x.y.z','😀.x.z','a'*16385,None])
def test_malformed_tokens(fixture_jwt: Any, token: Any) -> None:
    assert_deny(fixture_jwt,verify(fixture_jwt,token),DenyReason.BAD_SIGNATURE)


def test_jwt_header_injection_and_duplicates(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    _, payload, signature = token.split('.')
    for header in [b'{"alg":"EdDSA","alg":"EdDSA","kid":"fixture-kid","typ":"JWT"}',b'{"alg":"EdDSA","kid":"fixture-kid","typ":"JWT","jku":"https://attacker.invalid"}']:
        attack = base64.urlsafe_b64encode(header).rstrip(b'=').decode()+'.'+payload+'.'+signature
        assert_deny(fixture_jwt,verify(fixture_jwt,attack),DenyReason.BAD_SIGNATURE,token)


def test_digest_check_uses_constant_time_comparison(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with patch('app.core.grants.hmac.compare_digest',wraps=hmac.compare_digest) as compare:
        assert verify(fixture_jwt,token).allowed
        assert any(call.args == (fixture_jwt[3],fixture_jwt[3]) for call in compare.call_args_list)


def test_disabled_operator_cannot_verify(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with Session(fixture_jwt[1]) as session, session.begin():
        session.execute(update(User).where(User.id == 'human').values(active=False))
    assert_deny(fixture_jwt,verify(fixture_jwt,token),DenyReason.UNKNOWN_KEY,token)


def test_expired_does_not_burn_and_denied_context_can_retry(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    denied = verify(fixture_jwt,token,current_resource_version=2)
    assert_deny(fixture_jwt,denied,DenyReason.STALE_RESOURCE,token)
    assert verify(fixture_jwt,token).allowed


def test_external_audit_failure_rolls_back_before_denial(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    with Session(fixture_jwt[1]) as session, session.begin():
        with patch.object(fixture_jwt[0],'_audit',side_effect=RuntimeError('fixture outage')):
            result = fixture_jwt[0].verify_grant(token,fixture_jwt[3],'tenant-a',1,session=session)
        assert not result.allowed and result.reason is DenyReason.AUDIT_UNAVAILABLE
    with Session(fixture_jwt[1]) as session:
        assert session.get(UsedGrant,raw_claims(token)['jti']).status == 'ACTIVE'


def test_external_issuance_rollback_never_activates_token(fixture_jwt: Any) -> None:
    with pytest.raises(RuntimeError):
        with Session(fixture_jwt[1]) as session, session.begin():
            token = fixture_jwt[0].issue_grant(fixture_jwt[3],'human','tenant-a',1,session=session)
            raise RuntimeError('fixture rollback')
    assert_deny(fixture_jwt,verify(fixture_jwt,token),DenyReason.GRANT_USED)


def test_issuance_revoked_key_denied(fixture_jwt: Any) -> None:
    revoke_key(fixture_jwt[1],'fixture-kid')
    with pytest.raises(GrantIssueError,match='UNKNOWN_KEY'):
        make_token(fixture_jwt)


def test_missing_required_claim(fixture_jwt: Any) -> None:
    token = make_token(fixture_jwt)
    claims = raw_claims(token)
    del claims['max_uses']
    attack = jwt.encode(claims,fixture_jwt[2],algorithm='EdDSA',headers={'kid':'fixture-kid'})
    assert_deny(fixture_jwt,verify(fixture_jwt,attack),DenyReason.BAD_SIGNATURE,token)


def test_issue_from_encrypted_secret_file(fixture_jwt: Any, tmp_path: Any, monkeypatch: Any) -> None:
    from app.core.keys import generate_keypair
    monkeypatch.delenv('GRANT_PRIVATE_KEY_PEM')
    monkeypatch.setenv('GRANT_PRIVATE_KEY_FILE',str(tmp_path/'fixture-new-secret.pem'))
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PASSWORD','fixture-encrypted-secret-password')
    generate_keypair(fixture_jwt[1],'fixture-file-kid','human','tenant-a')
    service = GrantService(fixture_jwt[1],GrantSettings(issuer='fixture-issuer',policy_version='policy-1',signing_kid='fixture-file-kid'))
    token = service.issue_grant(fixture_jwt[3],'human','tenant-a',1)
    assert service.verify_grant(token,fixture_jwt[3],'tenant-a',1).allowed


@pytest.mark.parametrize('configuration',['absent','both','extraneous-password'])
def test_issuance_rejects_ambiguous_private_key_configuration(fixture_jwt: Any, monkeypatch: Any, configuration: str) -> None:
    if configuration == 'absent':
        monkeypatch.delenv('GRANT_PRIVATE_KEY_PEM')
    elif configuration == 'both':
        monkeypatch.setenv('GRANT_PRIVATE_KEY_FILE','fixture-private-source')
    else:
        monkeypatch.setenv('GRANT_PRIVATE_KEY_PASSWORD','fixture-password-on-unencrypted-key')
    with pytest.raises(GrantIssueError,match='UNKNOWN_KEY'):
        make_token(fixture_jwt)
    with Session(fixture_jwt[1]) as session:
        assert session.scalar(select(func.count()).select_from(UsedGrant)) == 0


def test_missing_configuration_is_typed_deny(fixture_jwt: Any, monkeypatch: Any) -> None:
    monkeypatch.delenv('GRANT_ISSUER')
    assert verify_grant('fixture-token',fixture_jwt[3],'tenant-a',1).reason is DenyReason.AUDIT_UNAVAILABLE
    with pytest.raises(GrantIssueError,match='AUDIT_UNAVAILABLE'):
        issue_grant(fixture_jwt[3],'human','tenant-a',1)
