"""Real Razorpay test-mode HTTP adapter; no simulated responses or fallback data."""
from typing import Any
import re
import httpx
import rfc8785
from pydantic import TypeAdapter
from app.core.timing import provider_span
from app.executor.config import ExecutorSettings
from app.executor.models import PaymentId, ProviderPayment, ProviderRefund, ProviderRejected, ProviderUncertain
from intentlock.schema import parse_json

_PAYMENT_ID = TypeAdapter(PaymentId)


class RazorpayTestAdapter:
    """Pinned HTTPS merchant API with no redirects or implicit POST retries."""
    def __init__(self, settings: ExecutorSettings, *, transport: httpx.BaseTransport | None = None):
        """Load credentials only in the trusted executor; transport injection is for tests."""
        self._client = httpx.Client(base_url='https://api.razorpay.com/v1/',auth=(settings.key_id,settings.key_secret),timeout=10,follow_redirects=False,transport=transport)

    def close(self) -> None:
        """Close executor-owned pooled connections without exposing configuration."""
        self._client.close()

    def _request(self, method: str, path: str, *, body: dict[str,Any] | None = None, reference: str | None = None) -> Any:
        with provider_span():
            return self._perform_request(method,path,body=body,reference=reference)

    def _perform_request(self, method: str, path: str, *, body: dict[str,Any] | None = None, reference: str | None = None) -> Any:
        headers = {'Content-Type':'application/json'}
        if reference is not None:
            headers['X-Refund-Idempotency'] = reference
        try:
            with self._client.stream(method,path,headers=headers,content=None if body is None else rfc8785.dumps(body)) as response:
                if response.status_code in {400,401,403,404,422}:
                    raise ProviderRejected('PROVIDER_REJECTED')
                if response.status_code >= 300:
                    raise ProviderUncertain('PROVIDER_UNCERTAIN')
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw)>2_000_000:
                        raise ProviderUncertain('PROVIDER_INVALID_RESPONSE')
            return parse_json(bytes(raw))
        except (ProviderRejected,ProviderUncertain):
            raise
        except Exception:
            raise ProviderUncertain('PROVIDER_UNCERTAIN') from None

    @staticmethod
    def _payment(value: Any) -> ProviderPayment:
        try:
            return ProviderPayment(provider_id=value['id'],amount_paise=value['amount'],amount_refunded_paise=value['amount_refunded'],currency=value['currency'],status=value['status'],created_at=value.get('created_at'))
        except Exception:
            raise ProviderUncertain('PROVIDER_INVALID_RESPONSE') from None

    @staticmethod
    def _refund(value: Any) -> ProviderRefund:
        try:
            return ProviderRefund(provider_id=value['id'],payment_id=value['payment_id'],amount_paise=value['amount'],currency=value['currency'],status=value['status'],receipt=value['receipt'])
        except Exception:
            raise ProviderUncertain('PROVIDER_INVALID_RESPONSE') from None

    def get_payment(self, payment_id: str) -> ProviderPayment:
        """GET the actual payment; identifiers cannot alter the request path."""
        payment_id = _PAYMENT_ID.validate_python(payment_id)
        payment = self._payment(self._request('GET','payments/'+payment_id))
        if payment.provider_id != payment_id:
            raise ProviderUncertain('PROVIDER_RESOURCE_MISMATCH')
        return payment

    def create_refund(self, payment_id: str, amount_paise: int, idempotency_ref: str) -> ProviderRefund:
        """POST a normal refund using Razorpay's documented idempotency header.

        Every retry uses exactly the same amount, speed, receipt and reference.
        No GET failure, timeout, redirect or unknown response fabricates success.
        """
        payment_id = _PAYMENT_ID.validate_python(payment_id)
        if type(amount_paise) is not int or not 0<amount_paise<=9007199254740991:
            raise ValueError('positive integer paise required')
        if not re.fullmatch(r'[A-Za-z0-9_-]{10,64}',idempotency_ref):
            raise ValueError('invalid provider idempotency reference')
        refund = self._refund(self._request('POST','payments/'+payment_id+'/refund',body={'amount':amount_paise,'speed':'normal','receipt':idempotency_ref},reference=idempotency_ref))
        if refund.payment_id != payment_id or refund.amount_paise != amount_paise or refund.receipt != idempotency_ref:
            raise ProviderUncertain('PROVIDER_RESOURCE_MISMATCH')
        return refund

    def find_refund(self, payment_id: str, idempotency_ref: str) -> ProviderRefund | None:
        """Search paginated real provider refunds; incomplete/ambiguous queries deny."""
        payment_id = _PAYMENT_ID.validate_python(payment_id)
        found: ProviderRefund | None = None
        # Bound work without mistaking an incomplete scan for proof of absence.
        for page in range(100):
            value = self._request('GET',f'payments/{payment_id}/refunds?count=100&skip={page*100}')
            if not isinstance(value,dict) or not isinstance(value.get('items'),list) or type(value.get('count')) is not int or value['count'] != len(value['items']):
                raise ProviderUncertain('PROVIDER_INVALID_RESPONSE')
            for item in value['items']:
                refund = self._refund(item)
                if refund.payment_id != payment_id:
                    raise ProviderUncertain('PROVIDER_RESOURCE_MISMATCH')
                if refund.receipt == idempotency_ref:
                    if found is not None and found.provider_id != refund.provider_id:
                        raise ProviderUncertain('PROVIDER_AMBIGUOUS_REFUND')
                    found = refund
            if len(value['items']) < 100:
                return found
        raise ProviderUncertain('PROVIDER_QUERY_INCOMPLETE')

    def list_refunds(self, payment_id: str) -> list[ProviderRefund]:
        """Fetch complete real provider evidence; fail if pagination is incomplete."""
        payment_id=_PAYMENT_ID.validate_python(payment_id)
        found={}
        for page in range(100):
            value=self._request('GET',f'payments/{payment_id}/refunds?count=100&skip={page*100}')
            if not isinstance(value,dict) or not isinstance(value.get('items'),list) or type(value.get('count')) is not int or value['count']!=len(value['items']):
                raise ProviderUncertain('PROVIDER_INVALID_RESPONSE')
            for item in value['items']:
                refund=self._refund(item)
                if refund.payment_id!=payment_id or refund.provider_id in found:
                    raise ProviderUncertain('PROVIDER_AMBIGUOUS_REFUND')
                found[refund.provider_id]=refund
            if len(value['items'])<100:
                return list(found.values())
        raise ProviderUncertain('PROVIDER_QUERY_INCOMPLETE')

    def create_order(self, amount_paise: int, receipt: str) -> dict[str,Any]:
        """Create a real test-mode order using a server-priced persisted basket."""
        if type(amount_paise) is not int or not 0<amount_paise<=10000000 or not re.fullmatch(r'[a-f0-9]{32}',receipt):
            raise ValueError('bounded order amount and checkout identifier required')
        value=self._request('POST','orders',body={'amount':amount_paise,'currency':'INR','receipt':receipt})
        if type(value) is not dict:raise ProviderUncertain('PROVIDER_INVALID_RESPONSE')
        return value

    def checkout_payment(self,payment_id: str) -> dict[str,Any]:
        """Read raw provider order binding in addition to the strict payment projection."""
        identifier=_PAYMENT_ID.validate_python(payment_id)
        value=self._request('GET','payments/'+identifier)
        if type(value) is not dict or value.get('id')!=identifier:raise ProviderUncertain('PROVIDER_INVALID_RESPONSE')
        self._payment(value)
        return value

    def order_payments(self,order_id: str) -> list[dict[str,Any]]:
        """Recover actual captured results when the browser callback is interrupted."""
        if not re.fullmatch(r'order_[A-Za-z0-9]+',order_id):raise ValueError('invalid order')
        value=self._request('GET','orders/'+order_id+'/payments')
        if type(value) is not dict or type(value.get('items')) is not list or value.get('count')!=len(value['items']) or len(value['items'])>100:
            raise ProviderUncertain('PROVIDER_INVALID_RESPONSE')
        for payment in value['items']:
            if type(payment) is not dict or payment.get('order_id')!=order_id:raise ProviderUncertain('PROVIDER_RESOURCE_MISMATCH')
        return value['items']
