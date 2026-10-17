"""Strict proposed actions and RFC 8785 canonical action digests.

Use ``parse_action`` or ``ProposedAction.model_validate_json`` on original wire
bytes: a dictionary cannot retain evidence of duplicate JSON members. NFC is an
application admission rule, not a transformation performed by JCS. Strings are
rejected rather than silently normalized. Schema and resource versions are
positive safe integers; choosing supported schema versions belongs to dispatch.
This module does not authorize actions or replace the existing gateway contract.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from rfc8785 import dumps as _jcs_dumps

MAX_SAFE_INTEGER = (1 << 53) - 1
MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER
PositiveInteger = Annotated[int, Field(strict=True, gt=0, le=MAX_SAFE_INTEGER)]
Identifier = Annotated[str, Field(strict=True, min_length=1)]


class Tool(StrEnum):
    """Supported proposed tools; additions require their own argument contract."""

    REFUND_CREATE = 'refund.create'


class Destination(StrEnum):
    """Refund destinations supported by the trusted effect contract."""

    ORIGINAL_PAYMENT = 'original_payment'


def _check_string(value: str) -> None:
    if not unicodedata.is_normalized('NFC', value):
        raise ValueError('NON_NFC_STRING')
    try:
        value.encode('utf-8', errors='strict')
    except UnicodeEncodeError as exc:
        raise ValueError('INVALID_UNICODE') from exc


def _check_tree(value: Any) -> None:
    """Check values before Pydantic or a serializer can coerce them."""
    if isinstance(value, _Contract):
        _check_tree(vars(value))
    elif isinstance(value, str):
        _check_string(value)
    elif type(value) is int:
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError('UNSAFE_INTEGER')
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError('INVALID_OBJECT_KEY')
            _check_string(key)
            _check_tree(child)
    elif isinstance(value, list):
        for child in value:
            _check_tree(child)
    elif value is not None:
        # Booleans are int subclasses; all fields here intentionally reject them.
        raise ValueError('INVALID_JSON_TYPE')


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError('DUPLICATE_KEY')
        result[key] = value
    return result


def _reject_number(_: str) -> Any:
    raise ValueError('INVALID_NUMBER')


def _load_json(raw: str | bytes | bytearray) -> Any:
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode('utf-8', errors='strict')
    if not isinstance(raw, str):
        raise ValueError('INVALID_JSON_INPUT')
    value = json.loads(raw, object_pairs_hook=_pairs,
                       parse_float=_reject_number, parse_constant=_reject_number)
    _check_tree(value)
    return value


class _Contract(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', frozen=True,
                              revalidate_instances='always')

    @model_validator(mode='before')
    @classmethod
    def _validate_tree(cls, value: Any) -> Any:
        _check_tree(value)
        return value

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Self:
        """Parse original JSON without losing duplicate keys or number syntax.

        Validation errors use Pydantic's ValidationError; wire-format errors use
        ValueError (including JSONDecodeError/UnicodeDecodeError subclasses).
        Lax validation and alternate unknown-field policies are not supported.
        """
        if kwargs.get('strict') is False or kwargs.get('extra', 'forbid') != 'forbid':
            raise ValueError('LAX_VALIDATION_FORBIDDEN')
        return cls.model_validate(_load_json(json_data), **kwargs)


class RefundArgs(_Contract):
    """Exact refund effect; amount is positive integer paise without coercion."""

    payment_id: Identifier
    amount_paise: PositiveInteger
    currency: Literal['INR']
    destination: Destination

    @field_validator('destination', mode='before')
    @classmethod
    def _destination_enum(cls, value: Any) -> Destination:
        if type(value) is str or isinstance(value, Destination):
            return Destination(value)
        raise ValueError('INVALID_DESTINATION')


class ProposedAction(_Contract):
    """Complete digest-bound proposal; it confers no authority to execute.

    All fields are required. Versions are positive safe integers, identifiers
    are nonempty NFC Unicode strings, and no identifier is normalized or trimmed.
    There is currently one tool, so its argument type is unambiguously RefundArgs.
    """

    v: PositiveInteger
    tool: Tool
    args: RefundArgs
    tenant_id: Identifier
    actor_id: Identifier
    resource_ref: Identifier
    resource_version: PositiveInteger

    @field_validator('tool', mode='before')
    @classmethod
    def _tool_enum(cls, value: Any) -> Tool:
        if type(value) is str or isinstance(value, Tool):
            return Tool(value)
        raise ValueError('INVALID_TOOL')


ActionInput = ProposedAction | dict[str, Any] | str | bytes | bytearray


def parse_action(action: ActionInput) -> ProposedAction:
    """Validate a proposal; use original JSON bytes to detect duplicate members.

    Instances are revalidated too, including models made using unsafe Pydantic
    construction/copy APIs. Directly calling a different JSON parser first loses
    duplicate-member evidence and is not a supported wire validation boundary.
    """
    if isinstance(action, (str, bytes, bytearray)):
        return ProposedAction.model_validate_json(action)
    return ProposedAction.model_validate(action)


def canonicalize(action: ActionInput) -> bytes:
    """Validate every field and return its RFC 8785 canonical UTF-8 bytes."""
    validated = parse_action(action)
    return _jcs_dumps(validated.model_dump(mode='json'))


def digest(action: ActionInput) -> str:
    """Return ``sha256:<lowercase hex>`` over the complete canonical action."""
    return 'sha256:' + hashlib.sha256(canonicalize(action)).hexdigest()
