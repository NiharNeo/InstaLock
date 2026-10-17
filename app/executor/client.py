"""Gateway RPC client; contains no provider configuration or credentials."""
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.errors import GatewayDenied
from app.core.policy import PaymentSnapshot
from app.executor.models import ProviderPayment
from app.executor.resources import apply_payment
from intentlock.db import Resource


class ExecutorClient:
    """Forward authenticated requests to the separately configured executor."""
    def __init__(self, url: str, token: str):
        """Bind the deployment-owned internal address and bearer credential."""
        self.client=httpx.Client(base_url=url.rstrip('/')+'/',headers={'Authorization':'Bearer '+token},timeout=30,follow_redirects=False)

    def call(self, path: str, body: dict[str, object]) -> dict[str, object]:
        """Fail closed on transport/protocol errors without leaking upstream details."""
        try:
            response=self.client.post(path,json=body)
            if len(response.content)>262144:
                raise ValueError('oversized executor response')
            result=response.json()
            if type(result) is not dict:
                raise ValueError('invalid response')
            if response.status_code>=300 and 'reason' not in result:
                raise ValueError('invalid denial')
            if path=='internal/execute':
                result['_http_status']=response.status_code
            elif response.status_code!=200:
                raise GatewayDenied(result.get('reason','EXECUTOR_UNAVAILABLE'),'executor.rpc',503)
            return result
        except GatewayDenied:
            raise
        except Exception:
            raise GatewayDenied('EXECUTOR_UNAVAILABLE','executor.rpc',503) from None

    def fetch(self, session: Session, payment_id: str, tenant_id: str, *, for_update: bool = False) -> PaymentSnapshot:
        """Read actual provider state and fence concurrent cache changes before applying."""
        cached=session.get(Resource,payment_id)
        observed=cached.version_hash if cached else None
        live=ProviderPayment.model_validate(self.call('internal/payments/get',{'payment_id':payment_id,'tenant_id':tenant_id}))
        current=session.scalar(select(Resource).where(Resource.id==payment_id).with_for_update().execution_options(populate_existing=True))
        if (current.version_hash if current else None)!=observed:
            raise GatewayDenied('STALE_RESOURCE','executor.cache_fence')
        return apply_payment(session,live,tenant_id)
