"""Immutable deterministic policy snapshots loaded from versioned YAML."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Mapping

import yaml
from pydantic import Field, model_validator
from yaml.tokens import AliasToken, AnchorToken

from app.core.canonical import MAX_SAFE_INTEGER, PositiveInteger, ProposedAction, _Contract, parse_action


class RuleIds(_Contract):
    """Every configurable rule is named in the policy artifact."""
    tenant_scope: str = Field(min_length=1, max_length=100)
    tool_allowlist: str = Field(min_length=1, max_length=100)
    resource_binding: str = Field(min_length=1, max_length=100)
    resource_version: str = Field(min_length=1, max_length=100)
    destination: str = Field(min_length=1, max_length=100)
    currency: str = Field(min_length=1, max_length=100)
    max_refund: str = Field(min_length=1, max_length=100)
    refundable_remaining: str = Field(min_length=1, max_length=100)
    one_in_flight: str = Field(min_length=1, max_length=100)
    read_scope: str = Field(min_length=1, max_length=100)
    refund_allow: str = Field(min_length=1, max_length=100)
    default_deny: str = Field(min_length=1, max_length=100)


class TenantRules(_Contract):
    """Actual deployment tenant permissions; no implicit scopes or limits."""
    tools: list[Literal['refund.create']]
    max_refund_paise: PositiveInteger
    read_scopes: list[Literal['payment.read']]


class PolicyDocument(_Contract):
    """Unambiguous policy file schema; missing tenants always deny."""
    schema_version: Literal[1]
    default: Literal['deny']
    rules: RuleIds
    tenants: dict[Annotated[str, Field(min_length=1, max_length=128)], TenantRules]


class PaymentSnapshot(_Contract):
    """Trusted, validated current effect state returned by the resource adapter."""
    payment_id: str = Field(min_length=1, max_length=128)
    order_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    currency: str = Field(min_length=1)
    original_destination: str = Field(min_length=1, max_length=128)
    destination_kind: str = Field(min_length=1)
    paid_paise: PositiveInteger
    refunded_paise: Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)]
    order_version: PositiveInteger
    in_flight_refunds: Annotated[int, Field(strict=True, ge=0, le=1)]

    version_hash: str | None = Field(default=None,pattern=r'^[0-9a-f]{64}$')
    provider_status: str | None = None

    @model_validator(mode='after')
    def _balance(self) -> PaymentSnapshot:
        if self.refunded_paise > self.paid_paise:
            raise ValueError('invalid refundable balance')
        return self

    @property
    def remaining_refundable_paise(self) -> int:
        """Compute the current balance in exact integer paise."""
        return self.paid_paise - self.refunded_paise


@dataclass(frozen=True)
class Decision:
    """An explicit allow/deny with the exact immutable policy and fired rule."""
    allowed: bool
    reason: str
    rule_id: str
    policy_version: str


@dataclass(frozen=True)
class _Tenant:
    tools: frozenset[str]
    max_refund_paise: int
    read_scopes: frozenset[str]


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueLoader, node: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result or key == '<<':
            raise ValueError('ambiguous YAML mapping')
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


@dataclass(frozen=True)
class PolicyEngine:
    """Pure policy evaluation; no network calls, credentials, or model decisions."""
    policy_version: str
    rules: Mapping[str, str]
    tenants: Mapping[str, _Tenant]

    @classmethod
    def load(cls, path: Path) -> PolicyEngine:
        """Hash exact file bytes and reject invalid/duplicate/aliased YAML at startup."""
        raw = path.read_bytes()
        if len(raw) > 1_000_000:
            raise ValueError('policy file too large')
        text = raw.decode('utf-8', errors='strict')
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
            raise ValueError('YAML anchors and aliases are forbidden')
        document = PolicyDocument.model_validate(yaml.load(text, Loader=_UniqueLoader))
        identifiers = document.rules.model_dump()
        if len(set(identifiers.values())) != len(identifiers):
            raise ValueError('rule identifiers must be unique')
        tenants: dict[str, _Tenant] = {}
        for tenant, config in document.tenants.items():
            if len(set(config.tools)) != len(config.tools) or len(set(config.read_scopes)) != len(config.read_scopes):
                raise ValueError('duplicate tool or read scope')
            tenants[tenant] = _Tenant(frozenset(config.tools), config.max_refund_paise, frozenset(config.read_scopes))
        return cls('sha256:' + hashlib.sha256(raw).hexdigest(), MappingProxyType(identifiers), MappingProxyType(tenants))

    def decision(self, allowed: bool, reason: str, rule: str) -> Decision:
        """Construct a decision identifying one configured rule."""
        return Decision(allowed, reason, self.rules[rule], self.policy_version)

    def evaluate(self, action: ProposedAction, resource: PaymentSnapshot, tenant_id: str) -> Decision:
        """Evaluate refund rules in fixed order; any ambiguity or exception denies.

        The per-payment cap is cumulative: refunded + proposed <= configured cap.
        This prevents splitting a large refund into smaller authorized requests.
        """
        try:
            action = parse_action(action)
            resource = PaymentSnapshot.model_validate(resource)
            if action.v != 1:
                return self.decision(False, 'UNSUPPORTED_SCHEMA_VERSION', 'default_deny')
            config = self.tenants.get(tenant_id)
            if config is None or action.tenant_id != tenant_id or resource.tenant_id != tenant_id:
                return self.decision(False, 'TENANT_OUT_OF_SCOPE', 'tenant_scope')
            if action.tool.value not in config.tools:
                return self.decision(False, 'TOOL_NOT_ALLOWED', 'tool_allowlist')
            if action.args.payment_id != resource.payment_id or action.resource_ref != resource.order_id:
                return self.decision(False, 'RESOURCE_MISMATCH', 'resource_binding')
            if resource.provider_status is not None and resource.provider_status != 'captured':
                return self.decision(False, 'PAYMENT_NOT_CAPTURED', 'resource_binding')
            if action.resource_version != resource.order_version or resource.order_version == MAX_SAFE_INTEGER:
                return self.decision(False, 'STALE_RESOURCE', 'resource_version')
            if action.args.destination.value != 'original_payment' or resource.destination_kind != 'original_payment':
                return self.decision(False, 'DESTINATION_NOT_ORIGINAL', 'destination')
            if action.args.currency != resource.currency or resource.currency != 'INR':
                return self.decision(False, 'CURRENCY_MISMATCH', 'currency')
            if action.args.amount_paise + resource.refunded_paise > config.max_refund_paise:
                return self.decision(False, 'REFUND_LIMIT_EXCEEDED', 'max_refund')
            if resource.remaining_refundable_paise < action.args.amount_paise:
                return self.decision(False, 'INSUFFICIENT_REFUNDABLE', 'refundable_remaining')
            if resource.in_flight_refunds:
                return self.decision(False, 'REFUND_IN_FLIGHT', 'one_in_flight')
            return self.decision(True, 'REFUND_ALLOWED', 'refund_allow')
        except Exception:
            return self.decision(False, 'POLICY_ERROR', 'default_deny')

    def evaluate_read(self, *, scope: str, tenant_id: str, resource: PaymentSnapshot) -> Decision:
        """Allow only explicitly scoped tenant reads, with no human grant needed."""
        try:
            resource = PaymentSnapshot.model_validate(resource)
            config = self.tenants.get(tenant_id)
            if config is None or resource.tenant_id != tenant_id:
                return self.decision(False, 'TENANT_OUT_OF_SCOPE', 'tenant_scope')
            if scope not in config.read_scopes:
                return self.decision(False, 'READ_OUT_OF_SCOPE', 'read_scope')
            return self.decision(True, 'READ_ALLOWED', 'read_scope')
        except Exception:
            return self.decision(False, 'POLICY_ERROR', 'default_deny')
