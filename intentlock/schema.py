"""Strict wire contracts shared by the signer and gateway."""
import hashlib
import json
from typing import Annotated, Any, Literal
import rfc8785
from pydantic import BaseModel, ConfigDict, Field

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9_.:-]+$')]
Integer = Annotated[int, Field(ge=1, le=9007199254740991)]

class Strict(BaseModel):
    """Reject unknown fields and coercion."""
    model_config = ConfigDict(strict=True, extra="forbid")

class Action(Strict):
    """The complete refund effect, including original destination and version."""
    tool: Literal['refund.create']
    tenant_id: Identifier
    order_id: Identifier
    ticket_id: Identifier
    amount_paise: Integer
    currency: Literal['INR']
    destination: Identifier
    resource_version: Integer

class Grant(Strict):
    """Domain-separated, expiring consent signed by a registered human."""
    purpose: Literal['intentlock.grant.v1']
    audience: Literal['intentlock.gateway']
    grant_id: Identifier
    signer_id: Identifier
    tenant_id: Identifier
    action_digest: Annotated[str, Field(pattern='^[0-9a-f]{64}$')]
    policy_version: Identifier
    issued_at: Integer
    expires_at: Integer

class Envelope(Strict):
    """Untrusted execution request; the signature covers the full grant."""
    request_id: Identifier
    action: Action
    grant: Grant
    signature: Annotated[str, Field(min_length=88, max_length=88)]

def canonical(value: BaseModel | dict[str, Any]) -> bytes:
    """Serialize using RFC 8785 without Unicode normalization."""
    return rfc8785.dumps(value.model_dump() if isinstance(value, BaseModel) else value)

def digest(value: BaseModel | dict[str, Any]) -> str:
    """Return SHA-256 of the canonical action or request."""
    return hashlib.sha256(canonical(value)).hexdigest()

def parse_json(raw: bytes) -> Any:
    """Reject duplicate JSON members and non-finite constants."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result
    def invalid(value: str) -> None:
        raise ValueError('non-finite JSON number')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)
