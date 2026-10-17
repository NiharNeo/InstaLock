"""Trusted provisioning CLI tests use only temporary synthetic fixture records."""
import json
import sys
from typing import Any
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.auth.cli import import_payments, main
from app.auth.service import provision_agent, provision_session, secret_hash
from app.core.keys import register_public_key
from intentlock.db import AgentServiceKey, OperatorSession, Payment


def test_provisioning_cli_and_insert_only_payments(fixture_context: Any, monkeypatch: Any, tmp_path: Any, capsys: Any) -> None:
    cfg,engine,key,_ = fixture_context
    monkeypatch.setenv('DATABASE_URL',cfg.database_url)
    register_public_key(engine,'fixture-cli-key','human','tenant-a',key.public_key())
    monkeypatch.setattr(sys,'argv',['auth','agent-key','--service-id','fixture-cli-service','--tenant-id','tenant-a','--actor-id','fixture-agent','--ttl','3600'])
    main()
    token = json.loads(capsys.readouterr().out)['agent_service_key']
    with Session(engine) as session:
        assert session.get(AgentServiceKey,'fixture-cli-service').token_hash == secret_hash(token)
    monkeypatch.setattr(sys,'argv',['auth','operator-session','--operator-id','human','--kid','fixture-cli-key','--ttl','3600'])
    main()
    credential = json.loads(capsys.readouterr().out)
    with Session(engine) as session:
        stored = session.get(OperatorSession,secret_hash(credential['session_token']))
        assert stored.csrf_hash == secret_hash(credential['csrf_token'])
    path = tmp_path/'fixture-payments.json'
    path.write_text(json.dumps([{'id':'fixture-payment','order_id':'order','tenant_id':'tenant-a','destination_kind':'original_payment','in_flight_refunds':0}]))
    monkeypatch.setattr(sys,'argv',['auth','import-payments',str(path)])
    main()
    with Session(engine) as session:
        assert session.get(Payment,'fixture-payment').order_id == 'order'
    with pytest.raises(Exception):
        main()


@pytest.mark.parametrize('ttl',[0,-1,1.0,True,9007199254740992])
def test_credential_ttls_are_strict(fixture_context: Any, ttl: Any) -> None:
    with Session(fixture_context[1]) as session, session.begin():
        with pytest.raises(ValueError):
            provision_agent(session,'fixture-service','tenant-a','agent',ttl)
        with pytest.raises(ValueError):
            provision_session(session,'missing','missing',ttl)


def test_payment_import_cross_tenant_or_missing_order_denied(fixture_context: Any, tmp_path: Any) -> None:
    for order,tenant in [('order','tenant-b'),('absent','tenant-a')]:
        path = tmp_path/'fixture-payment.json'
        path.write_text(json.dumps([{'id':'fixture-payment','order_id':order,'tenant_id':tenant,'destination_kind':'original_payment','in_flight_refunds':0}]))
        with Session(fixture_context[1]) as session, session.begin():
            with pytest.raises(ValueError,match='tenant mismatch'):
                import_payments(session,path)
