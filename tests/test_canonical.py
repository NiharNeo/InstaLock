"""Synthetic action fixtures and adversarial canonicalization regressions."""
import copy
import hashlib
import json
import unicodedata
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from app.core.canonical import (
    MAX_SAFE_INTEGER, Destination, ProposedAction, RefundArgs, Tool,
    canonicalize, digest, parse_action,
)


@pytest.fixture
def fixture_proposal() -> dict[str, Any]:
    """Synthetic business input used exclusively by these tests."""
    return {
        'v': 1, 'tool': 'refund.create',
        'args': {'payment_id': 'fixture-payment', 'amount_paise': 499,
                 'currency': 'INR', 'destination': 'original_payment'},
        'tenant_id': 'fixture-tenant', 'actor_id': 'fixture-human',
        'resource_ref': 'fixture-order', 'resource_version': 1,
    }


def test_key_reordering(fixture_proposal: dict[str, Any]) -> None:
    """Top-level and nested argument order do not affect canonical bytes."""
    reordered = dict(reversed(list(fixture_proposal.items())))
    reordered['args'] = dict(reversed(list(reordered['args'].items())))
    assert digest(reordered) == digest(fixture_proposal)
    assert canonicalize(reordered) == canonicalize(fixture_proposal)


def test_exact_bytes_and_digest(fixture_proposal: dict[str, Any]) -> None:
    expected = (b'{"actor_id":"fixture-human","args":{"amount_paise":499,'
                b'"currency":"INR","destination":"original_payment",'
                b'"payment_id":"fixture-payment"},"resource_ref":"fixture-order",'
                b'"resource_version":1,"tenant_id":"fixture-tenant",'
                b'"tool":"refund.create","v":1}')
    assert canonicalize(fixture_proposal) == expected
    assert digest(fixture_proposal) == 'sha256:' + hashlib.sha256(expected).hexdigest()
    model = parse_action(fixture_proposal)
    assert model.tool is Tool.REFUND_CREATE
    assert model.args.destination is Destination.ORIGINAL_PAYMENT
    assert digest(model) == digest(json.dumps(fixture_proposal))


@pytest.mark.parametrize('path,value', [
    (('args','amount_paise'),500), (('args','payment_id'),'different-payment'),
    (('v',),2), (('resource_version',),2), (('tenant_id',),'different-tenant'),
    (('actor_id',),'different-human'), (('resource_ref',),'different-order'),
])
def test_single_field_changes_digest(fixture_proposal: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    changed = copy.deepcopy(fixture_proposal)
    target = changed if len(path) == 1 else changed[path[0]]
    target[path[-1]] = value
    assert digest(changed) != digest(fixture_proposal)


def test_destination_is_bound_and_alternatives_rejected(fixture_proposal: dict[str, Any]) -> None:
    """There is no second valid destination whose action digest can be compared."""
    assert b'"destination":"original_payment"' in canonicalize(fixture_proposal)
    fixture_proposal['args']['destination'] = 'external_payment'
    for operation in (parse_action,canonicalize,digest):
        with pytest.raises(ValueError):
            operation(fixture_proposal)


@pytest.mark.parametrize('path', [('args','amount_paise'),('v',),('resource_version',)])
@pytest.mark.parametrize('invalid', ['499',499.0,True,False,None,0,-1,MAX_SAFE_INTEGER+1,-MAX_SAFE_INTEGER-1,float('nan'),float('inf'),float('-inf')])
def test_integer_fields_reject_ambiguous_values(fixture_proposal: dict[str, Any], path: tuple[str, ...], invalid: Any) -> None:
    target = fixture_proposal if len(path) == 1 else fixture_proposal[path[0]]
    target[path[-1]] = invalid
    with pytest.raises(ValueError):
        canonicalize(fixture_proposal)


def test_integer_499_and_safe_maximum_are_valid(fixture_proposal: dict[str, Any]) -> None:
    assert parse_action(fixture_proposal).args.amount_paise == 499
    for path in [('v',),('resource_version',),('args','amount_paise')]:
        target = fixture_proposal if len(path) == 1 else fixture_proposal[path[0]]
        target[path[-1]] = MAX_SAFE_INTEGER
    assert parse_action(canonicalize(fixture_proposal)).args.amount_paise == MAX_SAFE_INTEGER


@pytest.mark.parametrize('replacement', ['499.0','4.99e2','499e0','NaN','Infinity','-Infinity','9007199254740992'])
def test_wire_number_syntax_rejected(fixture_proposal: dict[str, Any], replacement: str) -> None:
    raw = json.dumps(fixture_proposal).replace('499',replacement)
    for operation in (ProposedAction.model_validate_json,parse_action,canonicalize,digest):
        with pytest.raises(ValueError):
            operation(raw)


@pytest.mark.parametrize('raw', [
    '{"v":1,"v":1}',
    '{"v":1,"\\u0076":1}',
    '{"args":{"payment_id":"first","payment_id":"second"}}',
    '{"args":{"amount_paise":499,"amount_paise":499}}',
])
def test_duplicate_keys_rejected_before_model_parsing(raw: str) -> None:
    for operation in (ProposedAction.model_validate_json,parse_action,canonicalize,digest):
        with pytest.raises(ValueError,match='DUPLICATE_KEY'):
            operation(raw.encode())


@pytest.mark.parametrize('location',['top','args'])
def test_unknown_fields_forbidden(fixture_proposal: dict[str, Any], location: str) -> None:
    target = fixture_proposal if location == 'top' else fixture_proposal['args']
    target['unexpected'] = 'value'
    with pytest.raises(ValidationError):
        ProposedAction.model_validate(fixture_proposal)
    with pytest.raises(ValueError):
        canonicalize(json.dumps(fixture_proposal))


@pytest.mark.parametrize('path', [('tenant_id',),('actor_id',),('resource_ref',),('args','payment_id')])
@pytest.mark.parametrize('text', ['e\u0301','A\u030a','\u212b','\u1100\u1161','a\u0315\u0300'])
def test_non_nfc_strings_rejected_without_rewriting(fixture_proposal: dict[str, Any], path: tuple[str, ...], text: str) -> None:
    assert not unicodedata.is_normalized('NFC',text)
    target = fixture_proposal if len(path) == 1 else fixture_proposal[path[0]]
    target[path[-1]] = text
    with pytest.raises(ValueError,match='NON_NFC_STRING'):
        ProposedAction.model_validate(fixture_proposal)
    with pytest.raises(ValueError,match='NON_NFC_STRING'):
        ProposedAction.model_validate_json(json.dumps(fixture_proposal))
    target[path[-1]] = unicodedata.normalize('NFC',text)
    assert parse_action(fixture_proposal)


@pytest.mark.parametrize('text',['\ud800','\udfff'])
def test_lone_surrogates_rejected(fixture_proposal: dict[str, Any], text: str) -> None:
    fixture_proposal['actor_id'] = text
    with pytest.raises(ValueError,match='INVALID_UNICODE'):
        digest(fixture_proposal)
    with pytest.raises(ValueError,match='INVALID_UNICODE'):
        digest(json.dumps(fixture_proposal))


def test_non_nfc_key_rejected() -> None:
    with pytest.raises(ValueError,match='NON_NFC_STRING'):
        parse_action('{"e\\u0301":"value"}')


def test_escaped_unicode_has_same_digest(fixture_proposal: dict[str, Any]) -> None:
    fixture_proposal['actor_id'] = 'é😀'
    assert digest(json.dumps(fixture_proposal,ensure_ascii=True)) == digest(json.dumps(fixture_proposal,ensure_ascii=False).encode())
    assert 'é😀'.encode() in canonicalize(fixture_proposal)


@pytest.mark.parametrize('field,value', [('tool','shell.execute'),('tool',1),('currency','USD'),('destination',1),('payment_id',499),('actor_id','')])
def test_other_contract_violations(fixture_proposal: dict[str, Any], field: str, value: Any) -> None:
    target = fixture_proposal if field in {'tool','actor_id'} else fixture_proposal['args']
    target[field] = value
    with pytest.raises(ValueError):
        digest(fixture_proposal)


@pytest.mark.parametrize('raw',[b'\xff', b'\xef\xbb\xbf{}', b'{} trailing', b'[]', b'null', b'true', b'{}{}'])
def test_invalid_wire_documents(raw: bytes) -> None:
    with pytest.raises(ValueError):
        parse_action(raw)


def test_no_lax_json_validation(fixture_proposal: dict[str, Any]) -> None:
    for options in ({'strict':False},{'extra':'ignore'}):
        with pytest.raises(ValueError,match='LAX_VALIDATION_FORBIDDEN'):
            ProposedAction.model_validate_json(json.dumps(fixture_proposal),**options)


def test_frozen_models_and_unchecked_copy_revalidation(fixture_proposal: dict[str, Any]) -> None:
    action = parse_action(fixture_proposal)
    with pytest.raises(ValidationError):
        action.actor_id = 'changed'
    with pytest.raises(ValidationError):
        action.args.amount_paise = 1
    for corrupted in (
        action.model_copy(update={'v':1.0}),
        action.model_copy(update={'actor_id':'e\u0301'}),
        action.model_copy(update={'unexpected':'value'}),
        action.model_copy(update={'args': action.args.model_copy(update={'amount_paise':499.0})}),
        ProposedAction.model_construct(**{**fixture_proposal,'resource_version':True}),
    ):
        with pytest.raises(ValueError):
            digest(corrupted)


# All generated business values are test fixtures, never application defaults.
nfc_identifier = st.text(st.characters(blacklist_categories=('Cs',)),min_size=1,max_size=48).map(lambda value: unicodedata.normalize('NFC',value))
valid_actions = st.builds(
    ProposedAction, v=st.integers(1,MAX_SAFE_INTEGER), tool=st.just(Tool.REFUND_CREATE),
    args=st.builds(RefundArgs,payment_id=nfc_identifier,amount_paise=st.integers(1,MAX_SAFE_INTEGER),currency=st.just('INR'),destination=st.just(Destination.ORIGINAL_PAYMENT)),
    tenant_id=nfc_identifier,actor_id=nfc_identifier,resource_ref=nfc_identifier,
    resource_version=st.integers(1,MAX_SAFE_INTEGER),
)


@given(action=valid_actions, ensure_ascii=st.booleans())
@settings(max_examples=300,deadline=None)
def test_property_round_trip_stability(action: ProposedAction, ensure_ascii: bool) -> None:
    wire = json.dumps(action.model_dump(mode='json'),ensure_ascii=ensure_ascii)
    restored = ProposedAction.model_validate_json(wire)
    assert restored == action
    assert digest(restored) == digest(action) == digest(wire.encode())
    assert canonicalize(restored) == canonicalize(action)
    assert canonicalize(canonicalize(action)) == canonicalize(action)


@given(action=valid_actions)
@settings(max_examples=200,deadline=None)
def test_property_reordering_and_actor_binding(action: ProposedAction) -> None:
    original = action.model_dump(mode='json')
    reordered = dict(reversed(list(original.items())))
    reordered['args'] = dict(reversed(list(original['args'].items())))
    assert digest(reordered) == digest(action)
    reordered['actor_id'] += ':different'
    assert digest(reordered) != digest(action)
