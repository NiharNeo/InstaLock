"""Fixture-only model-failure recovery without approval or duplicate submissions."""
import json,time
from typing import Any
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from app.agent.gemini import GeminiClient
from app.agent.worker import ProposalWorker,WorkerSettings
from intentlock.db import Ticket,ModelCall,Proposal,Refund
from test_intake_agent import fixture_intake,fixture_worker
from test_gateway_v1 import fixture_gateway,submit
from test_policy import fixture_policy_document,fixture_v1_action


def test_model_failure_schedules_bounded_retry(fixture_intake:Any)->None:
    """Three failed calls become visible failure; only due retries may be leased."""
    c=fixture_intake
    for attempt in range(3):
        worker,_,paths=fixture_worker(c,status=503)
        try:assert worker.once()
        finally:worker.close()
        with Session(c['engine']) as s,s.begin():
            ticket=s.get(Ticket,'ticket')
            assert ticket.processing_status==('RETRY_WAIT' if attempt<2 else 'MODEL_ERROR')
            if attempt<2:
                assert ticket.lease_until>int(time.time());ticket.lease_until=int(time.time())-1
        assert '/v1/proposals' not in paths
    with Session(c['engine']) as s:
        assert s.scalar(select(func.count()).select_from(ModelCall))==3
        assert s.scalar(select(func.count()).select_from(Proposal))==0
    result=c['client'].get('/v1/console',headers=c['operator']);assert result.status_code==200,result.text
    ticket=next(t for t in result.json()['tickets'] if t['id']=='ticket')
    assert ticket['status']=='MODEL_ERROR' and ticket['last_outcome']=='MODEL_ERROR'


def test_retry_requires_operator_csrf_and_fences_existing_proposal(fixture_intake:Any)->None:
    """Retry can requeue model work but cannot bypass authentication or duplicate a proposal."""
    c=fixture_intake;worker,_,_=fixture_worker(c,status=503)
    try:worker.once()
    finally:worker.close()
    endpoint='/v1/tickets/ticket/retry'
    assert c['client'].post(endpoint,json={},headers=c['agent']).status_code==401
    assert c['client'].post(endpoint,json={},headers=c['operator']).status_code>=400
    assert c['client'].post(endpoint,json={},headers=c['approval']).status_code==200
    with Session(c['engine']) as s,s.begin():
        row=s.get(Ticket,'ticket');assert row.processing_status=='QUEUED';row.processing_status='MODEL_ERROR'
    submit(c)
    assert c['client'].post(endpoint,json={},headers=c['approval']).json()['reason']=='TICKET_REVIEW_REQUIRED'
    with Session(c['engine']) as s:assert s.scalar(select(func.count()).select_from(Refund))==0


def test_uncertain_submission_never_auto_retries(fixture_intake:Any)->None:
    """A lost proposal response may hide a committed proposal and requires manual review."""
    c=fixture_intake;worker,_,_=fixture_worker(c,args={'payment_id':'payment','amount_paise':499,'reason':'Fixture'})
    original=worker._post
    def post(path:str,body:Any)->Any:
        response=original(path,body)
        if path=='v1/proposals':raise TimeoutError('fixture lost response')
        return response
    worker._post=post
    try:worker.once()
    finally:worker.close()
    with Session(c['engine']) as s:
        assert s.get(Ticket,'ticket').processing_status=='REVIEW_REQUIRED'
        assert s.scalar(select(ModelCall.outcome))=='SUBMISSION_UNCERTAIN'
        assert s.scalar(select(func.count()).select_from(Proposal))==1
    assert c['client'].post('/v1/tickets/ticket/retry',json={},headers=c['approval']).json()['reason']=='TICKET_NOT_RETRYABLE'


def test_flash_25_bounds_reasoning_and_validates_function()->None:
    """The tested 2.5 model gets its documented zero-thinking setting, with strict output checks."""
    import httpx
    captured=[]
    def provider(request:Any)->Any:
        captured.append(json.loads(request.content))
        return httpx.Response(200,json={'candidates':[{'finishReason':'STOP','content':{'parts':[{'functionCall':{'name':'propose_refund','args':{'payment_id':'fixture-payment','amount_paise':500,'reason':'Fixture'}}}]}}]})
    client=GeminiClient('gemini-2.5-flash','fixture-api-key',transport=httpx.MockTransport(provider))
    try:assert client.suggest({'redacted_text':'Fixture refund request','payment_id':'fixture-payment','remaining_refundable_paise':1000}).amount_paise==500
    finally:client.close()
    assert captured[0]['generationConfig']['thinkingConfig']=={'thinkingBudget':0}


def test_flash_38_low_thinking_leaves_room_for_function_output()->None:
    """Modern Flash must not exhaust a tiny token cap on thinking before a tool call."""
    import httpx
    captured=[]
    def provider(request:Any)->Any:
        captured.append(json.loads(request.content))
        return httpx.Response(200,json={'candidates':[{'finishReason':'STOP','content':{'parts':[{'functionCall':{'name':'propose_refund','args':{'payment_id':'fixture-payment','amount_paise':500,'reason':'Fixture'}}}]}}]})
    client=GeminiClient('gemini-3.8-flash','fixture-api-key',transport=httpx.MockTransport(provider))
    try:assert client.suggest({'redacted_text':'Fixture refund request','payment_id':'fixture-payment','remaining_refundable_paise':1000}).amount_paise==500
    finally:client.close()
    assert captured[0]['generationConfig']['thinkingConfig']=={'thinkingLevel':'low'}
    assert captured[0]['generationConfig']['maxOutputTokens']==4096


def test_flash_lite_uses_supported_minimal_thinking()->None:
    """The configured faster model preserves strict proposal validation and a minimal reasoning budget."""
    import httpx
    captured=[]
    def provider(request:Any)->Any:
        captured.append(json.loads(request.content))
        return httpx.Response(200,json={'candidates':[{'finishReason':'STOP','content':{'parts':[{'functionCall':{'name':'propose_refund','args':{'payment_id':'fixture-payment','amount_paise':500,'reason':'Fixture'}}}]}}]})
    client=GeminiClient('gemini-3.5-flash-lite','fixture-api-key',transport=httpx.MockTransport(provider))
    try:assert client.suggest({'redacted_text':'Fixture refund request','payment_id':'fixture-payment','remaining_refundable_paise':1000}).amount_paise==500
    finally:client.close()
    assert captured[0]['generationConfig']['thinkingConfig']=={'thinkingLevel':'minimal'}
