"""Fixture-only checks that stale proposal recovery never creates or reuses consent."""
from concurrent.futures import ThreadPoolExecutor
from typing import Any
import pytest
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from intentlock.db import Order,Proposal,ProposalPreview,UsedGrant,Refund
from app.core.receipts import verify_chain
from test_gateway_v1 import fixture_gateway,submit,preview,approve
from test_policy import fixture_policy_document,fixture_v1_action


def stale(context: Any) -> str:
    """Create a synthetic stale proposal by advancing only its fixture order version."""
    identifier=submit(context).json()['proposal_id']
    with Session(context['engine']) as session,session.begin():session.get(Order,'order').version+=1
    return identifier


def test_refresh_requires_new_human_preview_and_preserves_original(fixture_gateway: Any) -> None:
    """Refreshing changes only version/digest and leaves both old and new actions ungranted."""
    c=fixture_gateway;old=stale(c)
    assert preview(c,old).json()['reason']=='STALE_RESOURCE'
    result=c['client'].post('/v1/proposals/'+old+'/refresh',json={},headers=c['approval'])
    assert result.status_code==200,result.text
    new=result.json()['proposal_id'];assert new!=old
    with Session(c['engine']) as s:
        before=s.get(Proposal,old);after=s.get(Proposal,new)
        assert before.status=='SUPERSEDED' and after.status=='PENDING'
        assert before.action['resource_version']==1 and after.action['resource_version']==2
        assert before.action_digest!=after.action_digest
        assert {k:v for k,v in before.action.items() if k!='resource_version'}=={k:v for k,v in after.action.items() if k!='resource_version'}
        assert before.service_id==after.service_id
        assert before.grant_id is after.grant_id is None
        assert s.scalar(select(func.count()).select_from(UsedGrant))==0
        assert s.scalar(select(func.count()).select_from(Refund))==0
        assert s.get(ProposalPreview,(new,c['session_id'])) is None
        assert verify_chain(s,'tenant-a')['valid']
    assert preview(c,old).json()['reason']=='PROPOSAL_SUPERSEDED'
    assert approve(c,old).json()['reason']=='PROPOSAL_SUPERSEDED'
    assert approve(c,new).json()['reason']=='PREVIEW_REQUIRED'
    assert preview(c,new).status_code==200
    assert approve(c,new).status_code==200


@pytest.mark.parametrize('failure',['agent','csrf','extra','tenant','insufficient','approved'])
def test_refresh_failures_do_not_rewrite_proposals(fixture_gateway: Any,failure: str) -> None:
    """Services, missing CSRF, client edits, tenant escape and invalid policy cannot refresh."""
    c=fixture_gateway;identifier=submit(c).json()['proposal_id'];headers=c['approval'];body={}
    if failure=='approved':
        assert preview(c,identifier).status_code==200
        assert approve(c,identifier).status_code==200
    else:
        with Session(c['engine']) as s,s.begin():
            order=s.get(Order,'order');order.version+=1
            if failure=='insufficient':order.refunded_paise=order.paid_paise
            if failure=='tenant':s.get(Proposal,identifier).tenant_id='other-tenant'
    if failure=='agent':headers=c['agent']
    if failure=='csrf':headers=c['operator']
    if failure=='extra':body={'amount_paise':1}
    result=c['client'].post('/v1/proposals/'+identifier+'/refresh',json=body,headers=headers)
    assert result.status_code>=400,result.text
    with Session(c['engine']) as s:assert s.scalar(select(func.count()).select_from(Proposal))==1


def test_concurrent_refresh_creates_one_replacement(fixture_gateway: Any) -> None:
    """Concurrent refresh clicks retire the original once without issuing any grant."""
    c=fixture_gateway;old=stale(c)
    def refresh(_:int) -> int:return c['client'].post('/v1/proposals/'+old+'/refresh',json={},headers=c['approval']).status_code
    with ThreadPoolExecutor(max_workers=8) as pool:codes=list(pool.map(refresh,range(16)))
    assert codes.count(200)==1 and all(code in (200,409) for code in codes),codes
    with Session(c['engine']) as s:
        assert s.scalar(select(func.count()).select_from(Proposal))==2
        assert s.scalar(select(func.count()).select_from(UsedGrant))==0
