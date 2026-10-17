"""Database-backed, single-use Ed25519 JWT consent for canonical actions.

Verification consumes an ACTIVE grant. Supply a clean caller-owned transaction
when consumption must commit atomically with a business effect. Standalone calls
commit their decision and receipt before returning. No HTTP signing endpoint is
provided, and verification never loads a private key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Callable, Literal, TypeVar
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, TypeAdapter, model_validator
from sqlalchemy import select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.canonical import PositiveInteger, _Contract, _load_json
from app.core.keys import KeyIdentity, load_private_key, public_key_text
from app.core.receipts import append_receipt
from intentlock.db import KeyRegistry, Receipt, UsedGrant, User, engine_for

AUDIENCE = 'intentlock-gateway'
LIFETIME_SECONDS = 300
CLOCK_SKEW_SECONDS = 30
MAX_TOKEN_BYTES = 16384
Digest = Annotated[str, Field(strict=True, pattern=r'^sha256:[0-9a-f]{64}$')]
Name = Annotated[str, Field(strict=True, min_length=1, max_length=128)]
_DIGEST = TypeAdapter(Digest)
T = TypeVar('T')


class DenyReason(StrEnum):
    """Stable cryptographic, policy, replay, and operational denial codes."""
    BAD_SIGNATURE = 'BAD_SIGNATURE'
    ALG_NOT_ALLOWED = 'ALG_NOT_ALLOWED'
    EXPIRED = 'EXPIRED'
    WRONG_AUDIENCE = 'WRONG_AUDIENCE'
    WRONG_TENANT = 'WRONG_TENANT'
    ACTION_MISMATCH = 'ACTION_MISMATCH'
    STALE_RESOURCE = 'STALE_RESOURCE'
    GRANT_USED = 'GRANT_USED'
    UNKNOWN_KEY = 'UNKNOWN_KEY'
    INTERNAL_ERROR = 'INTERNAL_ERROR'
    AUDIT_UNAVAILABLE = 'AUDIT_UNAVAILABLE'


class GrantClaims(_Contract):
    """Strict required claims; a grant has exactly one use and a five-minute TTL."""
    iss: Name
    aud: str = Field(strict=True, min_length=1)
    sub: Name
    tid: Name
    jti: str
    iat: PositiveInteger
    exp: PositiveInteger
    act_digest: Digest
    res_ver: PositiveInteger
    max_uses: Literal[1]

    @model_validator(mode='after')
    def _invariants(self) -> GrantClaims:
        identifier = UUID(self.jti)
        if identifier.version != 4 or str(identifier) != self.jti:
            raise ValueError('jti must be a canonical UUID4')
        if self.exp - self.iat != LIFETIME_SECONDS:
            raise ValueError('grant TTL must be exactly 300 seconds')
        return self


class _Header(_Contract):
    alg: Literal['EdDSA']
    typ: Literal['JWT']
    kid: Name


@dataclass(frozen=True)
class GrantVerification:
    """An allow includes validated claims; every deny includes a stable reason."""
    allowed: bool
    reason: DenyReason | None
    claims: GrantClaims | None = None
    receipt_id: str | None = None

    def __post_init__(self) -> None:
        if self.allowed != (self.reason is None and self.claims is not None):
            raise ValueError('inconsistent verification result')
        if not self.allowed and (self.reason is None or self.claims is not None):
            raise ValueError('denial requires a reason and no trusted claims')


class GrantIssueError(ValueError):
    """Issuance failed; no usable token was returned or grant committed."""
    def __init__(self, reason: DenyReason):
        self.reason = reason
        super().__init__(reason.value)


class _Denied(Exception):
    def __init__(self, reason: DenyReason):
        self.reason = reason
        super().__init__(reason.value)


def _require(condition: bool, reason: DenyReason) -> None:
    if not condition:
        raise _Denied(reason)


class GrantSettings(_Contract):
    """Public verifier configuration; no private material is held in settings."""
    issuer: Name
    policy_version: Name
    signing_kid: Name | None = None

    @classmethod
    def from_env(cls) -> GrantSettings:
        """Read issuer/policy and optional signing kid without loading secrets."""
        return cls(issuer=os.environ['GRANT_ISSUER'], policy_version=os.environ['POLICY_VERSION'], signing_kid=os.environ.get('GRANT_SIGNING_KID') or None)


def _decode_segment(segment: str) -> bytes:
    if not re.fullmatch(r'[A-Za-z0-9_-]+', segment):
        raise ValueError('invalid JWT base64url')
    raw = base64.b64decode(segment + '=' * (-len(segment) % 4), altchars=b'-_', validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') != segment:
        raise ValueError('noncanonical JWT base64url')
    return raw


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class GrantService:
    """Dependency-injected grant issuer/verifier using the authoritative database."""

    def __init__(self, engine: Engine, settings: GrantSettings, *, private_key_loader: Callable[[], Ed25519PrivateKey] | None = None):
        """Bind a database and public configuration; signing secrets load on issue."""
        self.engine = engine
        self._private_key_loader = private_key_loader
        self.settings = GrantSettings.model_validate(settings)

    def _audit(self, session: Session, token: str, reason: str, allowed: bool, claims: GrantClaims | None = None) -> str:
        receipt_id = str(uuid4())
        # Receipts store no bearer token or signature; legacy digest column is hex.
        raw = token[:MAX_TOKEN_BYTES].encode('utf-8', errors='replace')
        append_receipt(session,tenant_id=claims.tid if claims else None,actor_id=claims.sub if claims else None,grant_jti=claims.jti if claims else None,id=receipt_id, timestamp=int(time.time()), allowed=allowed,
                            reason=reason, rule_id='grant.' + reason.lower(),
                            policy_version=session.info.get('effective_policy_version',self.settings.policy_version),
                            input_hash=hashlib.sha256(raw).hexdigest(),
                            action_digest=claims.act_digest.removeprefix('sha256:') if claims else None,
                            request_id=claims.jti if claims else None, refund_id=None)
        session.flush()
        return receipt_id

    def _deny(self, reason: DenyReason, token: str, session: Session | None = None) -> GrantVerification:
        try:
            if session is not None:
                with session.begin_nested():
                    receipt_id = self._audit(session, token, reason.value, False)
            else:
                with Session(self.engine) as audit, audit.begin():
                    receipt_id = self._audit(audit, token, reason.value, False)
            return GrantVerification(False, reason, receipt_id=receipt_id)
        except Exception:
            return GrantVerification(False, DenyReason.AUDIT_UNAVAILABLE)

    def _transaction(self, operation: Callable[[Session], T], session: Session | None) -> T:
        if session is not None:
            if not session.in_transaction():
                raise ValueError('caller-supplied session requires an explicit transaction')
            # A failed signature, compare-and-swap, or receipt write must roll back
            # any grant update before a denial is returned to the caller.
            with session.begin_nested():
                return operation(session)
        with Session(self.engine) as managed, managed.begin():
            result = operation(managed)
        return result  # Managed commit succeeded before exposing any allow/token.

    def issue_grant(self, action_digest: str, operator_id: str, tenant_id: str, resource_version: int, *, session: Session | None = None) -> str:
        """Sign a five-minute EdDSA JWT and insert its ACTIVE grant atomically.

        This is a trusted human-side primitive, not an authentication API. The
        caller must obtain human approval first. An optional external transaction
        stages the token; do not release it until the caller commits successfully.
        """
        def issue(db: Session) -> str:
            _require(self.settings.signing_kid is not None, DenyReason.UNKNOWN_KEY)
            assert self.settings.signing_kid is not None
            identity = KeyIdentity(kid=self.settings.signing_kid, operator_id=operator_id, tenant_id=tenant_id)
            registry = db.scalar(select(KeyRegistry).where(KeyRegistry.kid == identity.kid).with_for_update())
            _require(registry is not None and registry.active, DenyReason.UNKNOWN_KEY)
            assert registry is not None
            _require(registry.tenant_id == identity.tenant_id, DenyReason.WRONG_TENANT)
            _require(registry.operator_id == identity.operator_id, DenyReason.UNKNOWN_KEY)
            user = db.get(User, operator_id)
            _require(user is not None and user.active and user.tenant_id == tenant_id, DenyReason.UNKNOWN_KEY)
            now = int(time.time())
            claims = GrantClaims(iss=self.settings.issuer, aud=AUDIENCE, sub=operator_id,
                                 tid=tenant_id, jti=str(uuid4()), iat=now, exp=now + LIFETIME_SECONDS,
                                 act_digest=action_digest, res_ver=resource_version, max_uses=1)
            try:
                key = self._private_key_loader() if self._private_key_loader else load_private_key()
                _require(hmac.compare_digest(public_key_text(key.public_key()), registry.public_key), DenyReason.UNKNOWN_KEY)
            except (ValueError, TypeError, OSError):
                raise _Denied(DenyReason.UNKNOWN_KEY) from None
            token = jwt.encode(claims.model_dump(), key, algorithm='EdDSA', headers={'kid':identity.kid, 'typ':'JWT'})
            db.add(UsedGrant(id=claims.jti, payload=claims.model_dump(), signature=token.split('.')[2], status='ACTIVE', kid=identity.kid, token_hash=_token_hash(token), expires_at=claims.exp))
            self._audit(db, token, 'GRANT_ISSUED', True, claims)
            return token
        try:
            return self._transaction(issue, session)
        except _Denied as exc:
            denied = self._deny(exc.reason, '', session)
        except (ValueError, TypeError):
            denied = self._deny(DenyReason.BAD_SIGNATURE, '', session)
        except Exception:
            denied = self._deny(DenyReason.INTERNAL_ERROR, '', session)
        assert denied.reason is not None
        raise GrantIssueError(denied.reason)

    def _validate_token(self, session: Session, token: str, expected_digest: str, tenant_id: str, current_resource_version: int, *, required_status: str) -> GrantClaims:
        try:
            _require(isinstance(token, str) and len(token.encode()) <= MAX_TOKEN_BYTES, DenyReason.BAD_SIGNATURE)
            segments = token.split('.')
            _require(len(segments) == 3, DenyReason.BAD_SIGNATURE)
            header_data = _load_json(_decode_segment(segments[0]))
            _require(isinstance(header_data, dict), DenyReason.BAD_SIGNATURE)
            _require(header_data.get('alg') == 'EdDSA', DenyReason.ALG_NOT_ALLOWED)
            header = _Header.model_validate(header_data)
            payload = _load_json(_decode_segment(segments[1]))
            signature = _decode_segment(segments[2])
            _require(len(signature) == 64, DenyReason.BAD_SIGNATURE)
        except _Denied:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise _Denied(DenyReason.BAD_SIGNATURE) from None
        registry = session.scalar(select(KeyRegistry).where(KeyRegistry.kid == header.kid).with_for_update())
        _require(registry is not None and registry.active, DenyReason.UNKNOWN_KEY)
        assert registry is not None
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(registry.public_key, validate=True))
            decoded = jwt.decode(token, key, algorithms=['EdDSA'], options={
                'verify_signature':True, 'verify_exp':False, 'verify_iat':False,
                'verify_aud':False, 'verify_iss':False, 'verify_nbf':False,
                'verify_sub':False, 'verify_jti':False,
            })
            # All claim type, time and context validation is performed below,
            # after pinned Ed25519 signature verification, with the strict parser.
            _require(decoded == payload, DenyReason.BAD_SIGNATURE)
            claims = GrantClaims.model_validate(payload)
        except _Denied:
            raise
        except (jwt.PyJWTError, ValueError, TypeError):
            raise _Denied(DenyReason.BAD_SIGNATURE) from None
        _require(claims.iss == self.settings.issuer, DenyReason.BAD_SIGNATURE)
        _require(claims.aud == AUDIENCE, DenyReason.WRONG_AUDIENCE)
        now = int(time.time())
        _require(now < claims.exp + CLOCK_SKEW_SECONDS and claims.iat <= now + CLOCK_SKEW_SECONDS, DenyReason.EXPIRED)
        _require(type(tenant_id) is str and claims.tid == tenant_id == registry.tenant_id, DenyReason.WRONG_TENANT)
        _require(claims.sub == registry.operator_id, DenyReason.BAD_SIGNATURE)
        user = session.get(User, claims.sub)
        _require(user is not None and user.active and user.tenant_id == claims.tid, DenyReason.UNKNOWN_KEY)
        try:
            expected = _DIGEST.validate_python(expected_digest)
        except ValueError:
            raise _Denied(DenyReason.ACTION_MISMATCH) from None
        _require(hmac.compare_digest(claims.act_digest, expected), DenyReason.ACTION_MISMATCH)
        row = session.get(UsedGrant, claims.jti)
        _require(row is not None and row.status == required_status, DenyReason.GRANT_USED)
        assert row is not None
        _require(type(current_resource_version) is int and 0 < current_resource_version <= 9007199254740991 and claims.res_ver == current_resource_version, DenyReason.STALE_RESOURCE)
        _require(row.kid == header.kid and row.payload == claims.model_dump() and row.token_hash is not None and hmac.compare_digest(row.token_hash, _token_hash(token)) and row.signature == segments[2], DenyReason.BAD_SIGNATURE)
        return claims

    def validate_reserved_grant(self, session: Session, token: str, expected_digest: str, tenant_id: str, resource_version: int) -> GrantClaims:
        """Verify proof AFTER this transaction's successful ACTIVE->USED CAS.

        This is not standalone authorization: the caller must have changed one
        grant row and must insert its uniquely bound durable operation atomically.
        No side effect or provider call may occur before that transaction commits.
        """
        return self._validate_token(session,token,expected_digest,tenant_id,resource_version,required_status='USED')

    def _verify(self, session: Session, token: str, expected_digest: str, tenant_id: str, current_resource_version: int) -> GrantVerification:
        claims = self._validate_token(session,token,expected_digest,tenant_id,current_resource_version,required_status='ACTIVE')
        header = _Header.model_validate(_load_json(_decode_segment(token.split('.')[0])))
        active_key = select(KeyRegistry.kid).where(KeyRegistry.kid == header.kid, KeyRegistry.active.is_(True)).exists()
        active_user = select(User.id).where(User.id == claims.sub, User.tenant_id == claims.tid, User.active.is_(True)).exists()
        consumed = session.execute(update(UsedGrant).where(UsedGrant.id == claims.jti, UsedGrant.status == 'ACTIVE', UsedGrant.kid == header.kid, UsedGrant.token_hash == _token_hash(token), active_key, active_user).values(status='USED'))
        _require(consumed.rowcount == 1, DenyReason.GRANT_USED)
        receipt_id = self._audit(session, token, 'GRANT_CONSUMED', True, claims)
        return GrantVerification(True, None, claims, receipt_id)

    def verify_grant(self, token: str, expected_digest: str, tenant_id: str, current_resource_version: int, *, session: Session | None = None) -> GrantVerification:
        """Verify and atomically consume exactly one ACTIVE grant, or return a deny.

        Maximum time leeway is fixed at 30 seconds; future issuance beyond that
        and expiry at or after exp+30 are denied. With an external transaction,
        the returned allow is provisional until its business effect and receipt
        commit. Rollback restores ACTIVE status. Malformed claims use
        BAD_SIGNATURE; missing or inactive grant rows use GRANT_USED.
        """
        audit_token = token if isinstance(token, str) else ''
        try:
            return self._transaction(lambda db: self._verify(db, token, expected_digest, tenant_id, current_resource_version), session)
        except _Denied as exc:
            return self._deny(exc.reason, audit_token, session)
        except Exception:
            return self._deny(DenyReason.INTERNAL_ERROR, audit_token, session)


def issue_grant(action_digest: str, operator_id: str, tenant_id: str, resource_version: int) -> str:
    """Issue and commit a grant using environment configuration on a human host."""
    engine = None
    try:
        settings = GrantSettings.from_env()
        engine = engine_for(os.environ['DATABASE_URL'])
        return GrantService(engine, settings).issue_grant(action_digest, operator_id, tenant_id, resource_version)
    except GrantIssueError:
        raise
    except Exception:
        raise GrantIssueError(DenyReason.AUDIT_UNAVAILABLE) from None
    finally:
        if engine is not None:
            engine.dispose()


def verify_grant(token: str, expected_digest: str, tenant_id: str, current_resource_version: int) -> GrantVerification:
    """Verify/consume via public configuration only; never load signing secrets."""
    engine = None
    try:
        settings = GrantSettings.from_env()
        engine = engine_for(os.environ['DATABASE_URL'])
        return GrantService(engine, settings).verify_grant(token, expected_digest, tenant_id, current_resource_version)
    except Exception:
        return GrantVerification(False, DenyReason.AUDIT_UNAVAILABLE)
    finally:
        if engine is not None:
            engine.dispose()
