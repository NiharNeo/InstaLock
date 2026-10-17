"""Isolated proposal worker: Gateway service key and Gemini key, never signing/DB keys."""
import argparse
import logging
from dataclasses import dataclass, field
import os
import time
from typing import Any
from urllib.parse import urlsplit
import httpx
from app.agent.gemini import GeminiClient, InvalidProposal


@dataclass(frozen=True)
class WorkerSettings:
    """Minimal explicit configuration with no provider or signing secret fields."""
    gateway_url: str
    service_key: str = field(repr=False)
    model: str
    gemini_key: str = field(repr=False)

    @classmethod
    def from_env(cls) -> 'WorkerSettings':
        """Refuse privileged inherited environments, rather than reading their secrets."""
        forbidden=('DATABASE_URL','EXECUTOR_AUTH_TOKEN','RAZORPAY_','GRANT_PRIVATE_','GRANT_KEY_FILE_MAP','RECEIPT_PRIVATE_','SIGNING_KEY_')
        if any(value and any(name==prefix or name.startswith(prefix) for prefix in forbidden) for name,value in os.environ.items()):
            raise ValueError('agent must run with a minimal isolated environment')
        return cls(os.environ['GATEWAY_URL'],os.environ['AGENT_SERVICE_KEY'],os.environ['GEMINI_MODEL'],os.environ['GEMINI_API_KEY'])


class ProposalWorker:
    """Fixed gateway routes only; the model cannot choose URLs or invoke execution."""
    def __init__(self,settings: WorkerSettings,*,gateway_transport: httpx.BaseTransport | None = None,model_transport: httpx.BaseTransport | None = None):
        """Keep gateway and model credentials in separate HTTP clients."""
        endpoint=urlsplit(settings.gateway_url)
        if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path not in {'','/'} or not endpoint.hostname or (endpoint.scheme!='https' and not (endpoint.scheme=='http' and endpoint.hostname in {'gateway','localhost','127.0.0.1','::1'})) or len(settings.service_key)<40:
            raise ValueError('protected gateway origin and actual service key required')
        self.model=GeminiClient(settings.model,settings.gemini_key,transport=model_transport)
        self.client=httpx.Client(base_url=settings.gateway_url.rstrip('/')+'/',headers={'Authorization':'Bearer '+settings.service_key},timeout=45,follow_redirects=False,transport=gateway_transport)

    def _post(self,path: str,body: dict[str,Any]) -> httpx.Response:
        return self.client.post(path,json=body)

    def once(self) -> bool:
        """Process one leased redacted ticket and persist model metrics plus a receipt."""
        response=self._post('v1/agent/tickets/claim',{})
        response.raise_for_status()
        ticket=response.json()['ticket']
        if ticket is None:
            return False
        started=time.perf_counter_ns()
        suggestion=None
        try:
            suggestion=self.model.suggest(ticket)
            outcome='NO_PROPOSAL' if suggestion is None else 'PROPOSAL_SUBMITTED'
        except InvalidProposal:
            outcome='INVALID_PROPOSAL'
        except Exception as error:
            logging.warning('Model request failed (%s)',type(error).__name__)
            outcome='MODEL_ERROR'
        latency_ms=(time.perf_counter_ns()-started)//1000000
        # Authorization fields come from trusted context, never from model arguments.
        if suggestion is not None:
            action={'v':1,'tool':'refund.create','args':{'payment_id':ticket['payment_id'],'amount_paise':suggestion.amount_paise,'currency':'INR','destination':'original_payment'},'tenant_id':ticket['tenant_id'],'actor_id':ticket['actor_id'],'resource_ref':ticket['resource_ref'],'resource_version':ticket['resource_version']}
            try:
                proposed=self._post('v1/proposals',action)
                outcome='PROPOSAL_SUBMITTED' if proposed.status_code==201 else 'POLICY_DENIED'
            except Exception:
                outcome='SUBMISSION_UNCERTAIN'  # A proposal may exist; never automatically resubmit it.
        metrics={name:self.model.usage.get(name) for name in ('input_tokens','output_tokens','total_tokens')}
        result=self._post('v1/agent/model-calls',{'ticket_id':ticket['ticket_id'],'claim_token':ticket['claim_token'],'model':self.model.model,'latency_ms':latency_ms,'outcome':outcome,**metrics})
        result.raise_for_status()  # Stop if audit cannot persist; never silently discard it.
        return True

    def close(self) -> None:
        """Close both isolated HTTP clients."""
        self.client.close()
        self.model.close()


def main() -> None:
    """Run once or poll the actual gateway queue without loading a database driver."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    worker=ProposalWorker(WorkerSettings.from_env())
    try:
        while True:
            processed=worker.once()
            if args.once:
                return
            if not processed:
                time.sleep(15)
    finally:
        worker.close()


if __name__=='__main__':
    main()
