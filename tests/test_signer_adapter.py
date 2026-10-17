"""Fixture-only signer and model adapter tests; no real provider is called."""
import base64
import json
import sys
from typing import Any
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from intentlock import agent, operator
from intentlock.schema import Envelope, canonical, digest, parse_json
from intentlock.transport import NoRedirect, fetch_json


@pytest.fixture
def fixture_signer_files(fixture_context: Any, fixture_action: Any, tmp_path: Any, monkeypatch: Any) -> Any:
    """Encrypted fixture key and a human review command isolated from production."""
    cfg, _, key, _ = fixture_context
    password = 'fixture-password-for-testing'
    key_path = tmp_path/'fixture-private.pem'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode())))
    action_path = tmp_path/'fixture-action.json'
    action_path.write_bytes(canonical(fixture_action))
    output = tmp_path/'fixture-envelope.json'
    for name,value in {'SIGNING_KEY_PATH':str(key_path),'SIGNING_KEY_PASSWORD':password,'GATEWAY_URL':'http://localhost:8000','OPERATOR_TOKEN':cfg.operator_token}.items():
        monkeypatch.setenv(name,value)
    monkeypatch.setattr(sys,'argv',['operator','sign',str(action_path),'--signer-id','human','--grant-id','fixture-grant','--request-id','fixture-request','--ttl','120','--output',str(output)])
    preview = {'action':fixture_action,'action_digest':digest(fixture_action),'policy_version':cfg.policy_version}
    return output, preview, key


def test_signer_requires_exact_human_review(fixture_signer_files: Any) -> None:
    output, preview, _ = fixture_signer_files
    with patch('intentlock.operator.fetch_json',return_value=preview), patch('builtins.input',return_value='yes'):
        with pytest.raises(ValueError,match='human did not approve'):
            operator.main()
    assert not output.exists()


def test_signer_signature_and_no_overwrite(fixture_signer_files: Any) -> None:
    output, preview, key = fixture_signer_files
    with patch('intentlock.operator.fetch_json',return_value=preview), patch('builtins.input',return_value=preview['action_digest']):
        operator.main()
        with pytest.raises(FileExistsError):
            operator.main()
    body = Envelope.model_validate(parse_json(output.read_bytes()))
    key.public_key().verify(base64.b64decode(body.signature),canonical(body.grant))
    assert body.grant.action_digest == digest(body.action)


def test_signer_rejects_mismatched_preview(fixture_signer_files: Any) -> None:
    output, preview, _ = fixture_signer_files
    preview['action_digest'] = '0'*64
    with patch('intentlock.operator.fetch_json',return_value=preview):
        with pytest.raises(ValueError,match='preview mismatch'):
            operator.main()
    assert not output.exists()


@pytest.mark.parametrize('url',['http://remote.invalid/api','file:///etc/passwd','https://user:pass@remote.invalid','https://remote.invalid/#secret'])
def test_transport_rejects_unsafe_destinations(url: str) -> None:
    with pytest.raises(ValueError):
        fetch_json(url,'fixture-token')


def test_transport_never_follows_redirects() -> None:
    with pytest.raises(ValueError,match='redirects'):
        NoRedirect().redirect_request(None,None,302,'',None,'https://other.invalid')


def test_model_adapter_only_proposes(monkeypatch: Any) -> None:
    """The old entrypoint delegates to the redacted worker; no raw-context bypass."""
    from app.agent.worker import WorkerSettings
    monkeypatch.setattr(sys,'argv',['agent','--once'])
    config=WorkerSettings('http://localhost:8000','a'*48,'fixture-model','fixture-key')
    with patch('app.agent.worker.WorkerSettings.from_env',return_value=config), patch('app.agent.worker.ProposalWorker') as worker:
        agent.main()
        worker.assert_called_once_with(config)
        worker.return_value.once.assert_called_once_with()
        worker.return_value.close.assert_called_once_with()
