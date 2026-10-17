"""Durable refund authorization, crash-safe provider dispatch and reconciliation."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import re
import time
from typing import Any
from uuid import uuid4

import rfc8785
from sqlalchemy import or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.canonical import ProposedAction, digest, parse_action
from app.core.errors import GatewayDenied
from app.core.grants import GrantClaims, GrantService, GrantSettings, _Denied
from app.core.business_policy import effective_policy,lock_tenant_policy
from app.core.policy import PaymentSnapshot, PolicyEngine
from app.executor.config import ExecutorSettings
from app.executor.models import ProviderRefund, ProviderRejected, ProviderUncertain, RefundProvider
from app.executor.resources import apply_payment
from app.core.receipts import append_receipt
from intentlock.db import AgentServiceKey, Operation, Order, Payment, Proposal, Receipt, Refund, Resource, UsedGrant


def request_digest(action: ProposedAction, token: str, service_id: str) -> str:
    """Bind tenant idempotency to the entire action, exact grant and caller service."""
    return hashlib.sha256(rfc8785.dumps({'action':action.model_dump(mode='json'),'grant_hash':hashlib.sha256(token.encode()).hexdigest(),'service_id':service_id})).hexdigest()


@dataclass(frozen=True)
class Reservation:
    """A committed intent; only its creator may initially dispatch it."""
    operation_id: str
    created: bool
    result: dict[str,Any]


class ExecutorService:
    """Trusted executor. No provider credentials or network calls reach agent code."""
    def __init__(self, engine: Engine, settings: ExecutorSettings, policy: PolicyEngine, provider: RefundProvider):
        """Bind one explicit test merchant/tenant, policy snapshot and real adapter."""
        self.engine,self.settings,self.policy,self.provider = engine,settings,policy,provider
        self.grants = GrantService(engine,GrantSettings(issuer=settings.issuer,policy_version=policy.policy_version))

    def audit(self, session: Session, reason: str, allowed: bool, *, operation: Operation | None = None, rule_id: str | None = None, input_hash: str | None = None) -> str:
        """Persist decision metadata without any bearer token or provider secret."""
        identifier = str(uuid4())
        append_receipt(session,tenant_id=self.settings.tenant_id,actor_id=operation.action.get("actor_id") if operation else None,grant_jti=operation.grant_jti if operation else None,operation_id=operation.id if operation else None,id=identifier,timestamp=int(time.time()),allowed=allowed,reason=reason,rule_id=rule_id or 'executor.'+reason.lower(),policy_version=operation.policy_version if operation else session.info.get('effective_policy_version',self.policy.policy_version),input_hash=input_hash or (operation.request_digest if operation else hashlib.sha256(b'').hexdigest()),action_digest=digest(parse_action(operation.action)).removeprefix('sha256:') if operation else None,request_id=operation.id if operation else None,refund_id=operation.provider_refund_id if operation else None)
        session.flush()
        return identifier

    def deny(self, error: GatewayDenied, raw: bytes = b'') -> dict[str,Any]:
        """Audit a fresh fail-closed denial after the failed transaction rolls back."""
        try:
            with Session(self.engine) as session,session.begin():
                from app.core.receipts import reserve_audit_transaction
                reserve_audit_transaction(session)
                try:effective_policy(session,self.policy,self.settings.tenant_id)
                except (ValueError,TypeError):
                    error=GatewayDenied('POLICY_INTEGRITY_ERROR','business.policy_integrity',503)
                    session.info['effective_policy_version']=self.policy.policy_version
                identifier = self.audit(session,error.reason,False,rule_id=error.rule_id,input_hash=hashlib.sha256(raw).hexdigest())
            return {'allowed':False,'reason':error.reason,'rule_id':error.rule_id,'policy_version':session.info.get('effective_policy_version',self.policy.policy_version),'receipt_id':identifier,'_http_status':error.status}
        except Exception:
            return {'allowed':False,'reason':'AUDIT_UNAVAILABLE','rule_id':'audit.required','policy_version':self.policy.policy_version,'_http_status':503}

    @staticmethod
    def _peek(token: str) -> GrantClaims:
        """Extract only a candidate jti; trust is established after CAS, before commit."""
        try:
            pieces = token.split('.')
            if len(pieces)!=3:
                raise ValueError('invalid JWT')
            raw = base64.b64decode(pieces[1]+'='*(-len(pieces[1])%4),altchars=b'-_',validate=True)
            return GrantClaims.model_validate_json(raw)
        except Exception:
            raise GatewayDenied('BAD_SIGNATURE','grant.bad_signature') from None

    @staticmethod
    def _copy_result(row: Operation) -> dict[str,Any]:
        return {**row.result,'_http_status':200 if row.status=='DONE' else 202 if row.status=='PENDING' else 403}

    def reserve(self, action: ProposedAction, token: str, idempotency_key: str, service_id: str) -> Reservation:
        """CAS USED and insert one PENDING operation in ONE transaction, before I/O.

        The conditional UPDATE is deliberately the first SQL statement. It also
        avoids SQLite deferred-read-to-write lock upgrades under many contenders.
        A failed proof/policy/provenance check rolls this transaction back.
        """
        action = parse_action(action)
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',idempotency_key):
            raise GatewayDenied('INVALID_IDEMPOTENCY_KEY','executor.idempotency',400)
        if action.tenant_id != self.settings.tenant_id:
            raise GatewayDenied('WRONG_TENANT','executor.tenant')
        claims_hint = self._peek(token)
        request_hash = request_digest(action,token,service_id)
        now = int(time.time())
        try:
            with Session(self.engine) as session,session.begin():
                lock_tenant_policy(session,action.tenant_id)
                policy=effective_policy(session,self.policy,action.tenant_id)
                changed = session.execute(update(UsedGrant).where(UsedGrant.id==claims_hint.jti,UsedGrant.status=='ACTIVE',UsedGrant.expires_at>now).values(status='USED'))
                agent = session.get(AgentServiceKey,service_id)
                if agent is None or not agent.active or agent.expires_at<=now:
                    raise GatewayDenied('UNAUTHENTICATED','executor.service',401)
                if agent.tenant_id != action.tenant_id or agent.actor_id != action.actor_id:
                    raise GatewayDenied('WRONG_TENANT','executor.service_scope')
                prior = session.scalar(select(Operation).where(Operation.tenant_id==action.tenant_id,Operation.idempotency_key==idempotency_key))
                if prior is not None:
                    if not hmac.compare_digest(prior.request_digest,request_hash) or prior.service_id != service_id:
                        raise GatewayDenied('IDEMPOTENCY_CONFLICT','executor.idempotency',409)
                    self.audit(session,'IDEMPOTENT_RETRY',prior.status=='DONE',operation=prior)
                    return Reservation(prior.id,False,self._copy_result(prior))
                if changed.rowcount!=1:
                    grant = session.get(UsedGrant,claims_hint.jti)
                    if grant is not None and grant.status=='ACTIVE' and grant.expires_at is not None and grant.expires_at<=now:
                        raise GatewayDenied('EXPIRED','grant.expired')
                    raise GatewayDenied('GRANT_USED','grant.grant_used')
                try:
                    verified = self.grants.validate_reserved_grant(session,token,digest(action),action.tenant_id,action.resource_version)
                except _Denied as error:
                    raise GatewayDenied(error.reason.value,'grant.'+error.reason.value.lower()) from None
                grant = session.get(UsedGrant,verified.jti)
                if grant is None or grant.expires_at != verified.exp:
                    raise GatewayDenied('BAD_SIGNATURE','grant.expiry_binding')
                proposal = session.scalar(select(Proposal).where(Proposal.grant_id==verified.jti,Proposal.tenant_id==action.tenant_id,Proposal.service_id==service_id))
                if proposal is None or proposal.status!='APPROVED' or proposal.action_digest!=digest(action):
                    raise GatewayDenied('PROPOSAL_NOT_APPROVED','executor.approved_proposal')
                if proposal.policy_version!=policy.policy_version:
                    raise GatewayDenied('POLICY_CHANGED','executor.approved_policy')
                resource = session.get(Resource,action.args.payment_id)
                if resource is None or resource.tenant_id!=action.tenant_id or not proposal.approved_version_hash or proposal.approved_amount_refunded_paise is None:
                    raise GatewayDenied('STALE_RESOURCE','executor.provider_approval_required')
                reserved = session.execute(update(Payment).where(Payment.id==action.args.payment_id,Payment.tenant_id==action.tenant_id,Payment.in_flight.is_(False)).values(in_flight=True))
                if reserved.rowcount!=1:
                    raise GatewayDenied('REFUND_IN_FLIGHT','executor.payment_reservation')
                identifier = str(uuid4())
                op = Operation(id=identifier,tenant_id=action.tenant_id,service_id=service_id,idempotency_key=idempotency_key,request_digest=request_hash,grant_jti=verified.jti,proposal_id=proposal.id,payment_id=action.args.payment_id,action=action.model_dump(mode='json'),approved_version_hash=proposal.approved_version_hash,refunded_before_paise=proposal.approved_amount_refunded_paise,policy_version=policy.policy_version,status='PENDING',reason='OPERATION_PENDING',result={},created_at=now,updated_at=now,dispatch_started_at=None,provider_refund_id=None,lease_owner=None,lease_until=None)
                session.add(op)
                proposal.status='EXECUTING'
                receipt_id = self.audit(session,'OPERATION_RESERVED',True,operation=op)
                op.result={'allowed':False,'reason':'OPERATION_PENDING','rule_id':'executor.operation_pending','policy_version':op.policy_version,'operation_id':op.id,'status':op.status,'receipt_id':receipt_id}
                result = self._copy_result(op)
            return Reservation(identifier,True,result)
        except IntegrityError:
            # A different grant can race on the tenant-wide idempotency key.
            # Its failed transaction restores ACTIVE; never publish a second op.
            with Session(self.engine) as session:
                prior = session.scalar(select(Operation).where(Operation.tenant_id==action.tenant_id,Operation.idempotency_key==idempotency_key))
                if prior is not None and hmac.compare_digest(prior.request_digest,request_hash) and prior.service_id==service_id:
                    return Reservation(prior.id,False,self._copy_result(prior))
            raise GatewayDenied('IDEMPOTENCY_CONFLICT','executor.idempotency',409) from None

    def execute(self, action: ProposedAction, token: str, idempotency_key: str, service_id: str) -> dict[str,Any]:
        """Reserve once, commit, and only then re-fetch/call the real provider."""
        try:
            reservation = self.reserve(action,token,idempotency_key,service_id)
            if not reservation.created:
                return reservation.result
            return self.run(reservation.operation_id)
        except GatewayDenied as error:
            return self.deny(error)
        except Exception:
            return self.deny(GatewayDenied('INTERNAL_ERROR','executor.exception',503))

    def refresh(self, payment_id: str) -> PaymentSnapshot:
        """Fetch outside SQL transactions and fence concurrent webhook/cache updates."""
        for _ in range(3):
            with Session(self.engine) as session:
                mapping = session.get(Payment,payment_id)
                cached = session.get(Resource,payment_id)
                if mapping is None or mapping.tenant_id!=self.settings.tenant_id:
                    raise GatewayDenied('RESOURCE_NOT_FOUND','executor.payment_scope',404)
                observed = cached.version_hash if cached else None
            live = self.provider.get_payment(payment_id)
            with Session(self.engine) as session,session.begin():
                # First write acquires the SQLite writer before any snapshot read.
                locked = session.execute(update(Payment).where(Payment.id==payment_id,Payment.tenant_id==self.settings.tenant_id).values(in_flight=Payment.in_flight))
                if locked.rowcount!=1:
                    raise GatewayDenied('RESOURCE_NOT_FOUND','executor.payment_scope',404)
                cached = session.get(Resource,payment_id)
                if (cached.version_hash if cached else None)!=observed:
                    continue
                return apply_payment(session,live,self.settings.tenant_id)
        raise ProviderUncertain('RESOURCE_SYNC_CONFLICT')

    def _claim(self, identifier: str) -> tuple[str | None,dict[str,Any]]:
        now,owner = int(time.time()),str(uuid4())
        with Session(self.engine) as session,session.begin():
            changed = session.execute(update(Operation).where(Operation.id==identifier,Operation.tenant_id==self.settings.tenant_id,Operation.status=='PENDING',or_(Operation.lease_until.is_(None),Operation.lease_until<=now)).values(lease_owner=owner,lease_until=now+60,updated_at=now))
            op = session.get(Operation,identifier)
            if op is None or op.tenant_id!=self.settings.tenant_id:
                raise GatewayDenied('OPERATION_NOT_FOUND','executor.operation_scope',404)
            return (owner if changed.rowcount==1 else None),self._copy_result(op)

    def _pending(self, identifier: str, owner: str, reason: str, refund: ProviderRefund | None = None) -> dict[str,Any]:
        with Session(self.engine) as session,session.begin():
            changed=session.execute(update(Operation).where(Operation.id==identifier,Operation.lease_owner==owner,Operation.status=='PENDING').values(lease_until=None,lease_owner=None,updated_at=int(time.time())))
            op = session.get(Operation,identifier)
            if op is None:
                raise GatewayDenied('OPERATION_NOT_FOUND','executor.operation_scope',404)
            if changed.rowcount!=1 or op.status!='PENDING':
                return self._copy_result(op)
            # A stale worker cannot publish a result after another owner took over.
            if op.lease_owner is not None:
                return self._copy_result(op)
            if refund is not None:
                op.provider_refund_id=refund.provider_id
            op.reason=reason
            receipt_id=self.audit(session,reason,False,operation=op)
            op.result={'allowed':False,'reason':reason,'rule_id':'executor.'+reason.lower(),'policy_version':op.policy_version,'operation_id':op.id,'status':'PENDING','receipt_id':receipt_id}
            return self._copy_result(op)

    def _finish(self, identifier: str, owner: str, reason: str, refund: ProviderRefund | None = None, *, rule_id: str | None = None) -> dict[str,Any]:
        with Session(self.engine) as session,session.begin():
            changed=session.execute(update(Operation).where(Operation.id==identifier,Operation.status=='PENDING',Operation.lease_owner==owner).values(status='DONE' if reason=='EXECUTED' else 'FAILED',reason=reason,lease_owner=None,lease_until=None,updated_at=int(time.time())))
            op=session.get(Operation,identifier)
            if op is None:
                raise GatewayDenied('OPERATION_NOT_FOUND','executor.operation_scope',404)
            if changed.rowcount!=1:
                return self._copy_result(op)
            if refund is not None:
                op.provider_refund_id=refund.provider_id
            done=op.status=='DONE'
            payment=session.get(Payment,op.payment_id)
            proposal=session.get(Proposal,op.proposal_id)
            if payment is None or proposal is None:
                raise GatewayDenied('RESOURCE_NOT_FOUND','executor.operation_binding')
            payment.in_flight=False
            proposal.status='EXECUTED' if done else 'FAILED'
            if done:
                if refund is None:
                    raise ValueError('actual processed refund required')
                order=session.get(Order,payment.order_id)
                if order is None:
                    raise ValueError('missing real order')
                session.add(Refund(id=refund.provider_id,grant_id=op.grant_jti,order_id=payment.order_id,amount_paise=refund.amount_paise,destination=order.destination))
            fired=rule_id or 'executor.'+reason.lower()
            receipt_id=self.audit(session,reason,done,operation=op,rule_id=fired)
            op.result={'allowed':done,'reason':reason,'rule_id':fired,'policy_version':op.policy_version,'operation_id':op.id,'status':op.status,'receipt_id':receipt_id,'refund_id':op.provider_refund_id,'action_digest':digest(parse_action(op.action))}
            return self._copy_result(op)

    def run(self, identifier: str, *, reconcile: bool = False) -> dict[str,Any]:
        """Lease and resolve one committed intent; every POST reuses its UUID key."""
        owner,current=self._claim(identifier)
        if owner is None:
            return current
        with Session(self.engine) as session:
            op=session.get(Operation,identifier)
            assert op is not None
            action=parse_action(op.action)
            dispatched=op.dispatch_started_at is not None
            refund_known=op.provider_refund_id is not None
            approved_hash=op.approved_version_hash
            before=op.refunded_before_paise
            policy_version=op.policy_version
            policy=effective_policy(session,self.policy,action.tenant_id)
        try:
            refund=self.provider.find_refund(action.args.payment_id,identifier) if reconcile or dispatched or refund_known else None
            if refund is not None:
                if refund.amount_paise!=action.args.amount_paise or refund.payment_id!=action.args.payment_id or refund.receipt!=identifier:
                    raise ProviderUncertain('PROVIDER_RESOURCE_MISMATCH')
                snapshot=self.refresh(action.args.payment_id)
                if refund.status=='processed':
                    if snapshot.refunded_paise < before+refund.amount_paise:
                        return self._pending(identifier,owner,'PROVIDER_STATE_PENDING',refund)
                    return self._finish(identifier,owner,'EXECUTED',refund)
                if refund.status=='failed':
                    return self._finish(identifier,owner,'PROVIDER_FAILED',refund)
                return self._pending(identifier,owner,'PROVIDER_PENDING',refund)
            snapshot=self.refresh(action.args.payment_id)
            if snapshot.version_hash!=approved_hash:
                if dispatched:
                    return self._pending(identifier,owner,'RECONCILIATION_REQUIRED')
                return self._finish(identifier,owner,'STALE_RESOURCE')
            if policy_version!=policy.policy_version:
                return self._pending(identifier,owner,'RECONCILIATION_REQUIRED') if dispatched else self._finish(identifier,owner,'POLICY_CHANGED')
            # Discount only this operation's own durable payment reservation.
            with Session(self.engine) as session:
                live_op=session.get(Operation,identifier)
                if live_op is None or live_op.status!='PENDING' or live_op.lease_owner!=owner:
                    return current
                payment=session.get(Payment,action.args.payment_id)
                reservation_lost=payment is None or not payment.in_flight
            if reservation_lost:
                return self._finish(identifier,owner,'RESERVATION_LOST')
            checked=PaymentSnapshot.model_validate({**snapshot.model_dump(),'in_flight_refunds':snapshot.in_flight_refunds-1})
            decision=policy.evaluate(action,checked,self.settings.tenant_id)
            if not decision.allowed:
                return self._pending(identifier,owner,'RECONCILIATION_REQUIRED') if dispatched else self._finish(identifier,owner,decision.reason,rule_id=decision.rule_id)
            with Session(self.engine) as session,session.begin():
                claimed=session.execute(update(Operation).where(Operation.id==identifier,Operation.status=='PENDING',Operation.lease_owner==owner,Operation.lease_until>int(time.time())).values(dispatch_started_at=op.dispatch_started_at or int(time.time())))
                if claimed.rowcount!=1:
                    return current
            # No SQL transaction remains open across this external side effect.
            dispatched=True
            refund=self.provider.create_refund(action.args.payment_id,action.args.amount_paise,identifier)
            if refund.amount_paise!=action.args.amount_paise or refund.payment_id!=action.args.payment_id or refund.receipt!=identifier:
                raise ProviderUncertain('PROVIDER_RESOURCE_MISMATCH')
            if refund.status=='failed':
                self.refresh(action.args.payment_id)
                return self._finish(identifier,owner,'PROVIDER_FAILED',refund)
            if refund.status=='pending':
                return self._pending(identifier,owner,'PROVIDER_PENDING',refund)
            snapshot=self.refresh(action.args.payment_id)
            if snapshot.refunded_paise < before+refund.amount_paise:
                return self._pending(identifier,owner,'PROVIDER_STATE_PENDING',refund)
            return self._finish(identifier,owner,'EXECUTED',refund)
        except ProviderRejected:
            return self._pending(identifier,owner,'RECONCILIATION_REQUIRED') if dispatched else self._finish(identifier,owner,'PROVIDER_REJECTED')
        except (ProviderUncertain,GatewayDenied):
            return self._pending(identifier,owner,'PROVIDER_UNCERTAIN')
        except Exception:
            # A POST may already have succeeded: never release or fail an unknown
            # outcome just because a receipt/connection/process step failed.
            try:
                return self._pending(identifier,owner,'RECONCILIATION_REQUIRED')
            except Exception:
                return {'allowed':False,'reason':'AUDIT_UNAVAILABLE','rule_id':'audit.required','policy_version':self.policy.policy_version,'operation_id':identifier,'status':'PENDING','_http_status':503}

    def reconcile(self, *, now: int | None = None) -> list[dict[str,Any]]:
        """Resolve intents older than 60 seconds by querying the provider first."""
        cutoff=(int(time.time()) if now is None else now)-60
        with Session(self.engine) as session:
            identifiers=list(session.scalars(select(Operation.id).where(Operation.tenant_id==self.settings.tenant_id,Operation.status=='PENDING',Operation.created_at<cutoff).order_by(Operation.created_at).limit(100)))
        return [self.run(identifier,reconcile=True) for identifier in identifiers]
