"""Receipt tamper, isolation and concurrency properties using fixture-only data."""
from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import time
from typing import Any
from uuid import uuid4
import pytest
import rfc8785
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session
from app.core.receipts import FIELDS, GENESIS, append_receipt, load_receipt_key, payload, verify_chain
from intentlock.db import Receipt, ReceiptHead
from test_gateway_v1 import fixture_gateway, submit
from test_policy import fixture_policy_document, fixture_v1_action


@pytest.fixture
def fixture_chain(fixture_context: Any):
    engine=fixture_context[1]
    def add(tenant='tenant-a',**changes):
        metadata=dict(id=str(uuid4()),timestamp=int(time.time()),allowed=True,reason='FIXTURE_ALLOWED',rule_id='fixture.rule',policy_version='fixture-policy',input_hash=hashlib.sha256(b'fixture').hexdigest(),action_digest='a'*64,request_id=None,refund_id=None)
        metadata.update(changes)
        with Session(engine) as session,session.begin():
            row=append_receipt(session,tenant_id=tenant,actor_id='fixture-actor',grant_jti='fixture-grant',operation_id='fixture-operation',**metadata)
            return row.id
    for _ in range(3):
        add()
    return engine,add


@pytest.mark.parametrize('field',FIELDS+('receipt_hash','signature'))
def test_editing_every_receipt_field_is_detected(fixture_chain,field):
    engine,_=fixture_chain
    with Session(engine) as session,session.begin():
        row=session.scalar(select(Receipt).where(Receipt.seq==2))
        if field in {'seq','timestamp','created_at'}:
            value=getattr(row,field)+10
        elif field=='allowed':
            value=False
        elif field=='tenant_id':
            value='tenant-other'
        elif field=='decision':
            value='DENY'
        else:
            value='b'*32 if field=='id' else 'tampered'
        session.execute(update(Receipt).where(Receipt.id==row.id).values(**{field:value}))
    with Session(engine) as session,session.begin():
        result=verify_chain(session,'tenant-a')
        assert not result['valid'],field
        assert result['first_broken_seq']==2, result


@pytest.mark.parametrize('seq',[1,2,3,'all'])
def test_deleting_first_middle_last_or_all_is_detected(fixture_chain,seq):
    engine,_=fixture_chain
    with Session(engine) as session,session.begin():
        statement=delete(Receipt).where(Receipt.tenant_id=='tenant-a')
        if seq!='all':
            statement=statement.where(Receipt.seq==seq)
        session.execute(statement)
    with Session(engine) as session,session.begin():
        result=verify_chain(session,'tenant-a')
        assert not result['valid']
        assert result['first_broken_seq']==(seq if seq!='all' else 1)


def test_independent_tenant_sequences_and_signatures(fixture_chain):
    engine,add=fixture_chain
    add('tenant-b')
    add('tenant-b')
    with Session(engine) as session,session.begin():
        for tenant,count in [('tenant-a',3),('tenant-b',2)]:
            rows=list(session.scalars(select(Receipt).where(Receipt.tenant_id==tenant).order_by(Receipt.seq)))
            assert [r.seq for r in rows]==list(range(1,count+1))
            assert rows[0].prev_hash==GENESIS
            for row in rows:
                expected=hashlib.sha256(rfc8785.dumps(payload(row))).hexdigest()
                assert expected==row.receipt_hash
                load_receipt_key().public_key().verify(base64.b64decode(row.signature),bytes.fromhex(expected))
            assert verify_chain(session,tenant)['valid']
        session.execute(delete(Receipt).where(Receipt.tenant_id=='tenant-a',Receipt.seq==2))
    with Session(engine) as session,session.begin():
        assert not verify_chain(session,'tenant-a')['valid']
        assert verify_chain(session,'tenant-b')['valid']


def test_concurrent_writers_allocate_unique_monotonic_sequence(fixture_chain):
    engine,add=fixture_chain
    with ThreadPoolExecutor(max_workers=50) as pool:
        ids=list(pool.map(lambda _:add(),range(50)))
    assert len(set(ids))==50
    with Session(engine) as session,session.begin():
        result=verify_chain(session,'tenant-a')
        assert result['valid'],result
        assert result['checked']==53


def test_decision_and_head_rollback_together(fixture_chain):
    engine,_=fixture_chain
    with pytest.raises(RuntimeError):
        with Session(engine) as session,session.begin():
            append_receipt(session,tenant_id='tenant-a',id='fixture-rollback',timestamp=1,allowed=False,reason='FIXTURE_DENY',rule_id='fixture.rule',policy_version='fixture',input_hash='a'*64,action_digest=None,request_id=None,refund_id=None)
            raise RuntimeError('fixture crash')
    with Session(engine) as session,session.begin():
        assert session.get(Receipt,'fixture-rollback') is None
        assert verify_chain(session,'tenant-a')['checked']==3


def test_rehashing_tampered_payload_cannot_forge_signature(fixture_chain):
    engine,_=fixture_chain
    with Session(engine) as session,session.begin():
        row=session.scalar(select(Receipt).where(Receipt.seq==2))
        row.reason_code='FORGED'
        row.receipt_hash=hashlib.sha256(rfc8785.dumps(payload(row))).hexdigest()
    with Session(engine) as session,session.begin():
        assert verify_chain(session,'tenant-a')['reason']=='BAD_RECEIPT_SIGNATURE'


def test_receipt_endpoints_auth_filters_pagination_and_tamper(fixture_gateway):
    c=fixture_gateway
    assert submit(c).status_code==201
    client=c['client']
    assert client.get('/v1/receipts',headers=c['agent']).status_code==401
    page=client.get('/v1/receipts?limit=1&decision=ALLOW&reason=PROPOSAL_ACCEPTED',headers=c['operator'])
    assert page.status_code==200,page.text
    items=page.json()['items']
    assert len(items)==1
    assert items[0]['tenant_id']=='tenant-a'
    assert 'text' not in items[0]
    assert items[0]['signature']
    assert client.get('/v1/receipts?tenant_id=tenant-other',headers=c['operator']).status_code==400
    assert client.get('/v1/receipts?limit=1&limit=2',headers=c['operator']).status_code==400
    result=client.get('/v1/receipts/verify',headers=c['operator'])
    assert result.status_code==200 and result.json()['valid'],result.text
    with Session(c['engine']) as session,session.begin():
        session.execute(delete(Receipt).where(Receipt.tenant_id=='tenant-a',Receipt.seq==1))
    broken=client.get('/v1/receipts/verify',headers=c['operator'])
    assert broken.status_code==200,broken.text
    assert not broken.json()['valid'] and broken.json()['first_broken_seq']==1


def test_missing_key_and_reusing_grant_key_fail_closed(fixture_chain,monkeypatch):
    _,add=fixture_chain
    pem=__import__('os').environ['RECEIPT_PRIVATE_KEY_PEM']
    monkeypatch.delenv('RECEIPT_PRIVATE_KEY_PEM')
    with pytest.raises(ValueError):
        add()
    monkeypatch.setenv('RECEIPT_PRIVATE_KEY_PEM',pem)
    monkeypatch.setenv('GRANT_PRIVATE_KEY_PEM',pem)
    monkeypatch.delenv('GRANT_PRIVATE_KEY_FILE',raising=False)
    with pytest.raises(ValueError,match='must differ'):
        add()


@pytest.mark.parametrize('query',['limit=0','limit=201','limit=1.0','after_seq=-1','after_seq=9007199254740992','decision=allow','reason=bad%20reason'])
def test_receipt_query_validation(fixture_gateway,query):
    c=fixture_gateway
    response=c['client'].get('/v1/receipts?'+query,headers=c['operator'])
    assert response.status_code==400,response.text
    assert response.json()['reason']=='INVALID_REQUEST'


def test_http_tenant_isolation_and_cursor(fixture_gateway):
    c=fixture_gateway
    assert submit(c).status_code==201
    with Session(c['engine']) as session,session.begin():
        append_receipt(session,tenant_id='tenant-b',id='fixture-other-tenant-receipt',timestamp=1,allowed=False,reason='FIXTURE_DENIED',rule_id='fixture.rule',policy_version='fixture-policy',input_hash='a'*64,action_digest=None,request_id=None,refund_id=None)
    for _ in range(2):
        assert submit(c).status_code==201
    first=c['client'].get('/v1/receipts?limit=1&reason=PROPOSAL_ACCEPTED',headers=c['operator']).json()
    assert first['next_after_seq']==first['items'][0]['seq']
    second=c['client'].get('/v1/receipts?limit=1&reason=PROPOSAL_ACCEPTED&after_seq='+str(first['next_after_seq']),headers=c['operator']).json()
    assert second['items'][0]['seq']>first['items'][0]['seq']
    assert all(row['tenant_id']=='tenant-a' for row in c['client'].get('/v1/receipts',headers=c['operator']).json()['items'])
    assert 'IGNORE POLICY' not in str(first)


def test_deleting_tail_prevents_new_decision_commit(fixture_chain):
    engine,add=fixture_chain
    with Session(engine) as session,session.begin():
        session.execute(delete(Receipt).where(Receipt.seq==3))
    with pytest.raises(ValueError,match='tail'):
        add()
    with Session(engine) as session,session.begin():
        assert not verify_chain(session,'tenant-a')['valid']


def test_legacy_receipts_are_not_falsely_verified(fixture_chain):
    engine,_=fixture_chain
    with Session(engine) as session,session.begin():
        session.add(Receipt(id='fixture-historical-unsigned',timestamp=1,allowed=False,reason='LEGACY',rule_id='fixture.rule',policy_version='fixture-policy',input_hash='a'*64,action_digest=None,request_id=None,refund_id=None))
    with Session(engine) as session,session.begin():
        assert verify_chain(session,None)['reason']=='LEGACY_UNSIGNED'
        assert verify_chain(session,'tenant-a')['valid']


def test_every_persisted_receipt_column_is_signed():
    assert set(FIELDS)==set(Receipt.__table__.columns.keys())-{'receipt_hash','signature'}


def test_snapshot_pagination_finishes_despite_inspection_audits(fixture_gateway):
    c=fixture_gateway
    for _ in range(3):
        assert submit(c).status_code==201
    first=c['client'].get('/v1/receipts?limit=1',headers=c['operator']).json()
    snapshot=first['snapshot_seq']
    seen=[row['id'] for row in first['items']]
    cursor=first['next_after_seq']
    while cursor is not None:
        page=c['client'].get(f'/v1/receipts?limit=1&after_seq={cursor}&snapshot_seq={snapshot}',headers=c['operator']).json()
        seen.extend(row['id'] for row in page['items'])
        cursor=page['next_after_seq']
        assert len(seen)<=snapshot
    assert len(seen)==snapshot==3
    assert len(set(seen))==len(seen)


def test_signing_outage_rolls_back_grant_and_refund(fixture_gateway,monkeypatch):
    from test_gateway_v1 import authorized, execute
    from intentlock.db import Order, UsedGrant, Refund
    c=fixture_gateway
    _,token=authorized(c)
    monkeypatch.delenv('RECEIPT_PRIVATE_KEY_PEM')
    result=execute(c,token)
    assert result.status_code==503,result.text
    assert result.json()['reason']=='AUDIT_UNAVAILABLE'
    with Session(c['engine']) as session:
        assert session.get(Order,'order').refunded_paise==0
        assert session.scalar(select(UsedGrant.status))=='ACTIVE'
        assert session.scalar(select(Refund.id)) is None
