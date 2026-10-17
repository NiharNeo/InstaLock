"""Fixture-only HTTPS workspace, published catalog and cross-origin boundary checks."""
import os
from dataclasses import replace
from typing import Any
from sqlalchemy.orm import Session
from intentlock.db import SupportChannel
from test_gateway_v1 import fixture_gateway
from test_policy import fixture_policy_document,fixture_v1_action


def test_public_metadata_only_publishes_explicit_active_channel(fixture_gateway:Any,monkeypatch:Any)->None:
    """The login page links only a deliberately published real channel, not all tenants."""
    c=fixture_gateway;g=c['app'].state.gateway;g.settings=replace(g.settings,origin='https://fixture-store.example.test')
    with Session(c['engine']) as s,s.begin():
        s.add(SupportChannel(id='fixture-shop',tenant_id='tenant-a',active=True))
        s.add(SupportChannel(id='other-shop',tenant_id='tenant-b',active=True))
    monkeypatch.setenv('PUBLIC_STORE_CHANNEL','fixture-shop')
    response=c['client'].get('/v1/auth/providers');assert response.status_code==200
    assert response.json()['workspace_url']=='https://fixture-store.example.test'
    assert response.json()['storefront_url']=='https://fixture-store.example.test/store/fixture-shop'
    assert 'other-shop' not in response.text
    monkeypatch.setenv('PUBLIC_STORE_CHANNEL','nonexistent')
    assert c['client'].get('/v1/auth/providers').json()['storefront_url'] is None


def test_public_console_keeps_authentication_and_origin_enforcement(fixture_gateway:Any)->None:
    """Publishing a route never makes operator data anonymous or cross-origin accessible."""
    c=fixture_gateway;g=c['app'].state.gateway;origin='https://fixture-store.example.test';g.settings=replace(g.settings,origin=origin)
    assert c['client'].get('/v1/console').status_code==401
    assert c['client'].get('/v1/console',headers=c['agent']).status_code==401
    assert c['client'].get('/v1/console',headers={**c['operator'],'Origin':origin}).status_code==200
    assert c['client'].get('/v1/console',headers={**c['operator'],'Origin':'https://evil.example.test'}).status_code==403
