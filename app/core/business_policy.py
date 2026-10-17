"""Versioned business restrictions layered under the deployment policy ceiling."""
import hashlib
from dataclasses import replace
from types import MappingProxyType
from typing import Annotated,Literal
import rfc8785
from pydantic import Field
from sqlalchemy import select,update
from sqlalchemy.orm import Session
from app.core.canonical import _Contract,PositiveInteger
from app.core.policy import PolicyEngine
from intentlock.db import BusinessRefundPolicy,RefundPolicyRevision,User


class RefundRules(_Contract):
    """Supported structured restrictions; free-form model instructions cannot authorize."""
    refund_window_days: Annotated[int,Field(strict=True,ge=1,le=3650)] | None
    max_refund_paise: PositiveInteger | None
    partial_refunds: Literal['allow','deny']


def lock_tenant_policy(session: Session,tenant: str) -> None:
    """Fence policy activation against grant/operation reservation using actual tenant users."""
    session.execute(update(User).where(User.tenant_id==tenant).values(active=User.active))


def effective_policy(session: Session,base: PolicyEngine,tenant: str) -> PolicyEngine:
    """Compose the exact active business revision with the immutable deployment policy."""
    head=session.get(BusinessRefundPolicy,tenant)
    if head is None:
        session.info['effective_policy_version']=base.policy_version
        return base
    revision=session.get(RefundPolicyRevision,head.revision_id)
    if revision is None or revision.tenant_id!=tenant:raise ValueError('invalid business policy head')
    rules=RefundRules.model_validate(revision.rules)
    hashed='sha256:'+hashlib.sha256(rfc8785.dumps(rules.model_dump())).hexdigest()
    if hashed!=revision.content_hash:raise ValueError('business policy integrity failure')
    version='sha256:'+hashlib.sha256(rfc8785.dumps([base.policy_version,revision.id,hashed])).hexdigest()
    tenants=dict(base.tenants)
    if tenant in tenants:
        current=tenants[tenant]
        tenants[tenant]=replace(current,max_refund_paise=min(current.max_refund_paise,rules.max_refund_paise) if rules.max_refund_paise is not None else current.max_refund_paise,refund_window_days=rules.refund_window_days,partial_refunds=rules.partial_refunds)
    session.info['effective_policy_version']=version
    return replace(base,policy_version=version,tenants=MappingProxyType(tenants))
