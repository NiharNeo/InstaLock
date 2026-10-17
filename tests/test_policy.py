"""Deterministic policy tests; business tenants and amounts are test fixtures only."""
import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest
import yaml
from app.core.canonical import parse_action
from app.core.policy import PaymentSnapshot, PolicyEngine


@pytest.fixture
def fixture_policy_document() -> dict[str,Any]:
    """Explicit synthetic policy deployment for isolated tests."""
    return {'schema_version':1,'default':'deny','rules':{name:'fixture.'+name for name in ['tenant_scope','tool_allowlist','resource_binding','resource_version','destination','currency','max_refund','refundable_remaining','one_in_flight','read_scope','refund_allow','default_deny']},'tenants':{'tenant-a':{'tools':['refund.create'],'max_refund_paise':100000,'read_scopes':['payment.read']}}}


@pytest.fixture
def fixture_policy(tmp_path: Any, fixture_policy_document: Any) -> PolicyEngine:
    path = tmp_path/'fixture-policy.yaml'
    path.write_text(yaml.safe_dump(fixture_policy_document))
    return PolicyEngine.load(path)


@pytest.fixture
def fixture_v1_action() -> dict[str,Any]:
    """Only fixture actions contain synthetic IDs and monetary amounts."""
    return {'v':1,'tool':'refund.create','args':{'payment_id':'payment','amount_paise':49900,'currency':'INR','destination':'original_payment'},'tenant_id':'tenant-a','actor_id':'agent-actor','resource_ref':'order','resource_version':1}


@pytest.fixture
def fixture_resource() -> PaymentSnapshot:
    return PaymentSnapshot(payment_id='payment',order_id='order',tenant_id='tenant-a',currency='INR',original_destination='original-payment',destination_kind='original_payment',paid_paise=100000,refunded_paise=0,order_version=1,in_flight_refunds=0)


def test_refund_allow_has_rule_and_policy_version(fixture_policy: Any, fixture_v1_action: Any, fixture_resource: Any) -> None:
    decision = fixture_policy.evaluate(parse_action(fixture_v1_action),fixture_resource,'tenant-a')
    assert decision.allowed and decision.reason == 'REFUND_ALLOWED'
    assert decision.rule_id == 'fixture.refund_allow' and decision.policy_version.startswith('sha256:')


@pytest.mark.parametrize('changes,reason,rule',[
    ({'tenant_id':'tenant-b'},'TENANT_OUT_OF_SCOPE','tenant_scope'),
    ({'payment_id':'other'},'RESOURCE_MISMATCH','resource_binding'),
    ({'order_id':'other'},'RESOURCE_MISMATCH','resource_binding'),
    ({'order_version':2},'STALE_RESOURCE','resource_version'),
    ({'destination_kind':'redirected'},'DESTINATION_NOT_ORIGINAL','destination'),
    ({'currency':'USD'},'CURRENCY_MISMATCH','currency'),
    ({'paid_paise':1000},'INSUFFICIENT_REFUNDABLE','refundable_remaining'),
    ({'refunded_paise':60000},'REFUND_LIMIT_EXCEEDED','max_refund'),
    ({'in_flight_refunds':1},'REFUND_IN_FLIGHT','one_in_flight'),
])
def test_each_refund_rule(fixture_policy: Any, fixture_v1_action: Any, fixture_resource: Any, changes: Any, reason: str, rule: str) -> None:
    resource = PaymentSnapshot.model_validate({**fixture_resource.model_dump(),**changes})
    decision = fixture_policy.evaluate(parse_action(fixture_v1_action),resource,'tenant-a')
    assert not decision.allowed and decision.reason == reason and decision.rule_id == 'fixture.'+rule


def test_tool_allowlist_default_deny(tmp_path: Any, fixture_policy_document: Any, fixture_v1_action: Any, fixture_resource: Any) -> None:
    fixture_policy_document['tenants']['tenant-a']['tools'] = []
    path = tmp_path/'fixture-deny-tools.yaml'
    path.write_text(yaml.safe_dump(fixture_policy_document))
    decision = PolicyEngine.load(path).evaluate(parse_action(fixture_v1_action),fixture_resource,'tenant-a')
    assert not decision.allowed and decision.reason == 'TOOL_NOT_ALLOWED' and decision.rule_id == 'fixture.tool_allowlist'


def test_unknown_tenant_and_unsupported_version(fixture_policy: Any, fixture_v1_action: Any, fixture_resource: Any) -> None:
    assert fixture_policy.evaluate(parse_action(fixture_v1_action),fixture_resource,'absent').reason == 'TENANT_OUT_OF_SCOPE'
    fixture_v1_action['v'] = 2
    assert fixture_policy.evaluate(parse_action(fixture_v1_action),fixture_resource,'tenant-a').reason == 'UNSUPPORTED_SCHEMA_VERSION'


def test_cumulative_cap_prevents_split_refunds(fixture_policy: Any, fixture_v1_action: Any, fixture_resource: Any) -> None:
    snapshot = PaymentSnapshot.model_validate({**fixture_resource.model_dump(),'paid_paise':200000,'refunded_paise':60000})
    assert fixture_policy.evaluate(parse_action(fixture_v1_action),snapshot,'tenant-a').reason == 'REFUND_LIMIT_EXCEEDED'


def test_reads_are_automatically_allowed_only_in_scope(fixture_policy: Any, fixture_resource: Any) -> None:
    allowed = fixture_policy.evaluate_read(scope='payment.read',tenant_id='tenant-a',resource=fixture_resource)
    assert allowed.allowed and allowed.reason == 'READ_ALLOWED' and allowed.rule_id == 'fixture.read_scope'
    assert fixture_policy.evaluate_read(scope='user.export',tenant_id='tenant-a',resource=fixture_resource).reason == 'READ_OUT_OF_SCOPE'
    assert fixture_policy.evaluate_read(scope='payment.read',tenant_id='tenant-b',resource=fixture_resource).reason == 'TENANT_OUT_OF_SCOPE'


def test_policy_exceptions_deny(fixture_policy: Any, fixture_v1_action: Any, fixture_resource: Any) -> None:
    with patch('app.core.policy.parse_action',side_effect=RuntimeError('fixture failure')):
        assert fixture_policy.evaluate(parse_action(fixture_v1_action),fixture_resource,'tenant-a').reason == 'POLICY_ERROR'
    with patch('app.core.policy.PaymentSnapshot.model_validate',side_effect=RuntimeError('fixture failure')):
        assert fixture_policy.evaluate_read(scope='payment.read',tenant_id='tenant-a',resource=fixture_resource).reason == 'POLICY_ERROR'


def test_exact_file_hash_immutable_snapshot(tmp_path: Any, fixture_policy_document: Any) -> None:
    path = tmp_path/'fixture-hash.yaml'
    path.write_text(yaml.safe_dump(fixture_policy_document))
    policy = PolicyEngine.load(path)
    assert policy.policy_version == 'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()
    old_version = policy.policy_version
    path.write_bytes(path.read_bytes()+b'\n# deployed revision\n')
    assert PolicyEngine.load(path).policy_version != old_version
    assert policy.policy_version == old_version
    with pytest.raises(TypeError):
        policy.tenants['tenant-b'] = policy.tenants['tenant-a']
    with pytest.raises(TypeError):
        policy.rules['max_refund'] = 'changed'


@pytest.mark.parametrize('suffix',['\ndefault: allow\n','\nextra: true\n','\ntenants: {}\n','\nx: &a {}\ny: *a\n'])
def test_ambiguous_or_unknown_yaml_rejected(tmp_path: Any, fixture_policy_document: Any, suffix: str) -> None:
    path = tmp_path/'fixture-invalid.yaml'
    path.write_text(yaml.safe_dump(fixture_policy_document)+suffix)
    with pytest.raises(ValueError):
        PolicyEngine.load(path)


@pytest.mark.parametrize('field,value',[('max_refund_paise',499.0),('max_refund_paise','499'),('max_refund_paise',True),('max_refund_paise',0),('max_refund_paise',9007199254740992),('tools',['shell.execute']),('tools',['refund.create','refund.create']),('read_scopes',['user.export'])])
def test_invalid_tenant_policy_rejected(tmp_path: Any, fixture_policy_document: Any, field: str, value: Any) -> None:
    fixture_policy_document['tenants']['tenant-a'][field] = value
    path = tmp_path/'fixture-invalid.yaml'
    path.write_text(yaml.safe_dump(fixture_policy_document))
    with pytest.raises(ValueError):
        PolicyEngine.load(path)


def test_checked_in_policy_contains_no_business_tenants(fixture_v1_action: Any, fixture_resource: Any) -> None:
    policy = PolicyEngine.load(Path('policies/refunds.yaml'))
    assert not policy.tenants
    assert not policy.evaluate(parse_action(fixture_v1_action),fixture_resource,'tenant-a').allowed
