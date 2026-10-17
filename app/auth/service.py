"""Least-privilege database identity checks; keys cannot become human sessions."""
from __future__ import annotations
import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request
from app.core.errors import GatewayDenied
from app.core.keys import KeyIdentity
from intentlock.db import AgentServiceKey, KeyRegistry, OperatorSession, User

SESSION_COOKIE = 'intentlock_session'


def secret_hash(value: str) -> str:
    """Hash an opaque high-entropy credential, never a human password."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class AgentIdentity:
    """Authenticated service and its immutable tenant/actor scope."""
    service_id: str
    tenant_id: str
    actor_id: str


@dataclass(frozen=True)
class HumanIdentity:
    """Authenticated active human session, tenant and registered signing kid."""
    session_id: str
    operator_id: str
    tenant_id: str
    signing_kid: str


def authenticate_agent(session: Session, request: Request) -> AgentIdentity:
    """Accept only active unexpired bearer service keys on the two agent routes."""
    header = request.headers.get('authorization','')
    if not header.startswith('Bearer ') or request.cookies.get(SESSION_COOKIE):
        raise GatewayDenied('UNAUTHENTICATED','auth.agent_key',401)
    token = header.removeprefix('Bearer ')
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,128}',token):
        raise GatewayDenied('UNAUTHENTICATED','auth.agent_key',401)
    row = session.scalar(select(AgentServiceKey).where(AgentServiceKey.token_hash == secret_hash(token)))
    if row is None or not row.active or row.expires_at <= int(time.time()):
        raise GatewayDenied('UNAUTHENTICATED','auth.agent_key',401)
    session.info.update(receipt_tenant=row.tenant_id,receipt_actor=row.actor_id)
    request.state.receipt_tenant=row.tenant_id
    request.state.receipt_actor=row.actor_id
    return AgentIdentity(row.id,row.tenant_id,row.actor_id)


def operator_session(session: Session, token: str) -> tuple[HumanIdentity,OperatorSession]:
    """Authenticate an existing opaque human session, never a service key."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,128}',token):
        raise GatewayDenied('UNAUTHENTICATED','auth.operator_session',401)
    row = session.get(OperatorSession,secret_hash(token))
    if row is None or not row.active or row.expires_at <= int(time.time()):
        raise GatewayDenied('UNAUTHENTICATED','auth.operator_session',401)
    user = session.get(User,row.user_id)
    if user is None or not user.active or user.tenant_id != row.tenant_id:
        raise GatewayDenied('UNAUTHENTICATED','auth.operator_session',401)
    session.info.update(receipt_tenant=row.tenant_id,receipt_actor=row.user_id)
    return HumanIdentity(row.id,row.user_id,row.tenant_id,row.signing_kid),row


def check_origin(request: Request, origin: str) -> None:
    """Reject cross-site browser requests while retaining nonbrowser API support."""
    request_origin = request.headers.get('origin')
    if (request_origin is not None and request_origin != origin) or request.headers.get('sec-fetch-site') == 'cross-site':
        raise GatewayDenied('CSRF_INVALID','auth.same_origin')


def check_csrf(request: Request, supplied: str, row: OperatorSession, origin: str) -> None:
    """Validate a high-entropy CSRF secret bound to this exact authenticated session."""
    check_origin(request,origin)
    if supplied and hmac.compare_digest(secret_hash(supplied),row.csrf_hash):
        return
    try:
        derived=session_csrf(row.id)
    except (KeyError,ValueError):
        derived=None
    if not supplied or derived is None or not hmac.compare_digest(derived,supplied):
        raise GatewayDenied('CSRF_INVALID','auth.csrf')


def authenticate_operator(session: Session, request: Request, *, csrf: bool = False, origin: str) -> HumanIdentity:
    """Accept an opaque DB session; approval also needs session-bound CSRF."""
    if request.headers.get('authorization'):
        raise GatewayDenied('UNAUTHENTICATED','auth.operator_session',401)
    cookies = request.headers.get('cookie','').split(';')
    if sum(part.strip().split('=',1)[0] == SESSION_COOKIE for part in cookies) != 1:
        raise GatewayDenied('UNAUTHENTICATED','auth.operator_session',401)
    identity,row = operator_session(session,request.cookies.get(SESSION_COOKIE,''))
    request.state.receipt_tenant=identity.tenant_id
    request.state.receipt_actor=identity.operator_id
    check_origin(request,origin)
    if csrf:
        check_csrf(request,request.headers.get('x-csrf-token',''),row,origin)
    return identity


def provision_agent(session: Session, service_id: str, tenant_id: str, actor_id: str, ttl: int) -> str:
    """Create a real service credential only through trusted administration."""
    KeyIdentity(kid=service_id,operator_id=actor_id,tenant_id=tenant_id)
    if type(ttl) is not int or not 0 < ttl <= 9007199254740991 - int(time.time()):
        raise ValueError('positive bounded credential TTL required')
    token = secrets.token_urlsafe(48)
    session.add(AgentServiceKey(id=service_id,tenant_id=tenant_id,actor_id=actor_id,token_hash=secret_hash(token),active=True,expires_at=int(time.time())+ttl))
    session.flush()
    return token


def provision_session(session: Session, operator_id: str, kid: str, ttl: int) -> tuple[str,str]:
    """Create an opaque human session only after trusted external authentication."""
    user = session.get(User,operator_id)
    key = session.get(KeyRegistry,kid)
    if user is None or not user.active or key is None or not key.active or key.operator_id != user.id or key.tenant_id != user.tenant_id:
        raise ValueError('active human and owned signing kid required')
    if type(ttl) is not int or not 0 < ttl <= 9007199254740991 - int(time.time()):
        raise ValueError('positive bounded session TTL required')
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    session.add(OperatorSession(id=secret_hash(token),user_id=user.id,tenant_id=user.tenant_id,signing_kid=kid,csrf_hash=secret_hash(csrf),active=True,expires_at=int(time.time())+ttl))
    session.flush()
    return token, csrf


def session_csrf(session_id: str) -> str:
    """Derive a stable session-bound CSRF token with a dedicated deployment HMAC secret."""
    secret=os.environ['SESSION_CSRF_SECRET']
    if len(secret)<32:
        raise ValueError('strong dedicated session CSRF secret required')
    return hmac.new(secret.encode(),('intentlock-session-csrf-v1:'+session_id).encode(),hashlib.sha256).hexdigest()
