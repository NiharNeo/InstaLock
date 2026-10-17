"""Fixture-only commerce security and provider verification tests."""
import hashlib,hmac,time
from types import SimpleNamespace
from typing import Any
import pytest
from sqlalchemy import select,func
from sqlalchemy.orm import Session
from app.commerce.executor import checkout_rpc
from app.executor.config import ExecutorSettings
from app.executor.razorpay import RazorpayTestAdapter
from app.core.errors import GatewayDenied
from intentlock.db import SupportChannel,StoreProduct,StoreCheckout,StoreSupportRequest,Payment,Order,Ticket,Refund,Resource
from test_gateway_v1 import fixture_gateway
from test_policy import fixture_policy_document,fixture_v1_action


class FixtureCommerceProvider:
    """Provider responses exist only in tests; tracks side-effect counts."""
    def __init__(self):self.creates=0;self.captured=False;self.value={}
    _payment=staticmethod(RazorpayTestAdapter._payment)
    def create_order(self,amount:int,receipt:str)->dict[str,Any]:
        self.creates+=1
        self.value={'id':'pay_storefixture','amount':amount,'amount_refunded':0,'currency':'INR','status':'captured','created_at':int(time.time()),'order_id':'order_storefixture'}
        return {'id':'order_storefixture','amount':amount,'currency':'INR','receipt':receipt}
    def checkout_payment(self,identifier:str)->dict[str,Any]:return self.value
    def order_payments(self,identifier:str)->list[dict[str,Any]]:return [self.value] if self.captured else []


@pytest.fixture
def fixture_store(fixture_gateway:Any,monkeypatch:Any)->Any:
    """Connect real commerce routes/transactions to a test-only provider boundary."""
    c=fixture_gateway;monkeypatch.setenv('INTAKE_RATE_SECRET','r'*32)
    p=FixtureCommerceProvider();g=c['app'].state.gateway
    service=SimpleNamespace(engine=c['engine'],provider=p,policy=g.policy,settings=SimpleNamespace(tenant_id='tenant-a',key_id='rzp_test_fixture',key_secret='fixture-secret'))
    class FixtureRPC:
        def call(self,path:str,body:dict[str,Any])->Any:return checkout_rpc(service,body,path.rsplit('/',1)[-1])
    g.executor=FixtureRPC()
    with Session(c['engine']) as s,s.begin():
        s.add(SupportChannel(id='fixture-shop',tenant_id='tenant-a',active=True))
        s.add(StoreProduct(id='fixture-product',tenant_id='tenant-a',name='Fixture product',category='Fixture category',description='Fixture description',price_paise=10000,active=True,created_at=int(time.time())))
        s.add(StoreProduct(id='other-product',tenant_id='tenant-b',name='Other fixture',category='Other fixture',description='Other fixture',price_paise=100,active=True,created_at=int(time.time())))
    client=c['client'];base='/public/store/fixture-shop';assert client.get(base+'/catalog').status_code==200
    return c,p,base,service


def create(c:Any,base:str,**changes:Any)->Any:
    """Create a persisted fixture basket through the real public route."""
    return c['client'].post(base+'/checkouts',json={'items':[{'product_id':'fixture-product','quantity':1}],'idempotency_key':'fixture-checkout-key',**changes})


def confirmation()->dict[str,str]:
    """Sign only test fixture provider identifiers."""
    return {'razorpay_order_id':'order_storefixture','razorpay_payment_id':'pay_storefixture','razorpay_signature':hmac.new(b'fixture-secret',b'order_storefixture|pay_storefixture',hashlib.sha256).hexdigest()}


def test_server_price_idempotency_capture_support_no_refund(fixture_store:Any)->None:
    """A real captured provider result links an order; support creates no refund or grant."""
    c,p,b,_=fixture_store;r=create(c,b);assert r.status_code==200,r.text;data=r.json();identifier=data['checkout_id']
    assert data['amount_paise']==10000 and p.creates==1
    assert create(c,b).json()['checkout_id']==identifier and p.creates==1
    assert c['client'].post(b+'/checkouts/'+identifier+'/confirm',json=confirmation()).json()['status']=='PAID'
    result=c['client'].post(b+'/checkouts/'+identifier+'/support',json={'product_id':'fixture-product','amount_paise':1000,'text':'Please refund ten rupees for this purchase.'})
    assert result.status_code==200,result.text
    with Session(c['engine']) as s:
        assert s.get(Payment,'pay_storefixture').order_id=='order_storefixture'
        assert s.get(Resource,'pay_storefixture').payment_created_at
        assert s.get(Ticket,result.json()['ticket_id']).order_id=='order_storefixture'
        assert s.get(StoreSupportRequest,result.json()['ticket_id']).requested_paise==1000
        assert s.scalar(select(func.count()).select_from(Refund))==0
    c['client'].cookies.clear()
    assert c['client'].get(b+'/catalog').status_code==200
    assert c['client'].get(b+'/orders').json()['orders']==[]
    assert c['client'].post(b+'/checkouts/'+identifier+'/status',json={}).status_code==404


@pytest.mark.parametrize('changes,reason',[
 ({'amount_paise':1},'INVALID_REQUEST'),
 ({'items':[{'product_id':'other-product','quantity':1}]},'PRODUCT_UNAVAILABLE'),
 ({'items':[{'product_id':'fixture-product','quantity':1.0}]},'INVALID_REQUEST'),
 ({'items':[{'product_id':'fixture-product','quantity':True}]},'INVALID_REQUEST'),
 ({'items':[{'product_id':'fixture-product','quantity':1},{'product_id':'fixture-product','quantity':1}]},'DUPLICATE_CART_ITEM'),
])
def test_cart_tampering(fixture_store:Any,changes:Any,reason:str)->None:
    """No customer price, cross-tenant product or coercion can create a provider order."""
    c,p,b,_=fixture_store;r=create(c,b,**changes);assert r.json()['reason']==reason,r.text;assert p.creates==0


def test_forged_signature_and_uncaptured(fixture_store:Any)->None:
    """Browser confirmation and support never replace provider capture proof."""
    c,p,b,_=fixture_store;identifier=create(c,b).json()['checkout_id'];path=b+'/checkouts/'+identifier
    bad={**confirmation(),'razorpay_signature':'0'*64}
    assert c['client'].post(path+'/confirm',json=bad).json()['reason']=='BAD_SIGNATURE'
    assert c['client'].post(path+'/status',json={}).json()['status']=='AWAITING_PAYMENT'
    assert c['client'].post(path+'/support',json={'product_id':'fixture-product','amount_paise':100,'text':'Refund please'}).json()['reason']=='PAYMENT_NOT_CAPTURED'
    p.value['status']='authorized'
    assert c['client'].post(path+'/confirm',json=confirmation()).json()['reason']=='PAYMENT_NOT_CAPTURED'


def test_callback_lost_recovers_provider_capture_and_category(fixture_store:Any)->None:
    """Provider polling recovers an interrupted browser callback without inventing payment."""
    c,p,b,_=fixture_store;identifier=create(c,b).json()['checkout_id'];p.captured=True
    assert c['client'].post(b+'/checkouts/'+identifier+'/status',json={}).json()['status']=='PAID'
    result=c['client'].get('/v1/store/catalog',headers=c['operator']);assert result.status_code==200,result.text
    assert result.json()['categories']==[{'category':'Fixture category','units':1,'sales_paise':10000}]
    assert 'other-product' not in result.text


def test_catalog_csrf_and_service_boundaries(fixture_store:Any)->None:
    """Catalog mutations require the operator, CSRF and strict monetary types."""
    c,p,b,_=fixture_store;body={'name':'Fixture authored','category':'Fixture','description':'Fixture','price_paise':499}
    assert c['client'].post('/v1/store/catalog',json=body,headers=c['agent']).status_code==401
    assert c['client'].post('/v1/store/catalog',json=body,headers=c['operator']).status_code>=400
    assert c['client'].post('/v1/store/catalog',json={**body,'price_paise':499.0},headers=c['approval']).status_code==400
    assert c['client'].post('/v1/store/catalog',json=body,headers=c['approval']).status_code==201


def test_duplicate_json_and_cross_origin(fixture_store:Any)->None:
    """Wire-level duplicate keys and unexpected origins fail before provider work."""
    c,p,b,_=fixture_store
    assert c['client'].post(b+'/checkouts',content='{"items":[],"items":[]}',headers={'Content-Type':'application/json'}).json()['reason']=='INVALID_REQUEST'
    assert c['client'].post(b+'/checkouts',json={},headers={'Origin':'https://evil.invalid'}).status_code>=400
    assert p.creates==0


def test_provider_amount_binding_and_ambiguous_creation_not_retried(fixture_store:Any)->None:
    """A mismatched provider payment is denied and an uncertain order is not re-created."""
    c,p,b,service=fixture_store;identifier=create(c,b).json()['checkout_id'];p.value['amount']=1
    assert c['client'].post(b+'/checkouts/'+identifier+'/confirm',json=confirmation()).json()['reason']=='RESOURCE_MISMATCH'
    with Session(c['engine']) as s,s.begin():s.get(StoreCheckout,identifier).status='CREATING';s.get(StoreCheckout,identifier).provider_order_id=None
    assert create(c,b).json()['reason']=='CHECKOUT_PENDING';assert p.creates==1


def test_basket_conflict_and_immutable_price(fixture_store:Any)->None:
    """Reusing a key with a different basket denies; existing priced orders never reprice."""
    c,p,b,_=fixture_store;first=create(c,b).json()
    conflict=create(c,b,items=[{'product_id':'fixture-product','quantity':2}])
    assert conflict.json()['reason']=='IDEMPOTENCY_CONFLICT'
    with Session(c['engine']) as s,s.begin():s.get(StoreProduct,'fixture-product').price_paise=20000
    assert create(c,b).json()['amount_paise']==10000
    assert p.creates==1


def test_fifty_executor_creations_reserve_one_order(fixture_store:Any)->None:
    """Concurrent retries cannot issue a second provider order POST."""
    from concurrent.futures import ThreadPoolExecutor
    c,p,b,service=fixture_store;identifier=create(c,b).json()['checkout_id']
    with Session(c['engine']) as s,s.begin():
        row=s.get(StoreCheckout,identifier);row.status='REQUESTED';row.provider_order_id=None
    p.creates=0
    def attempt(_:int)->str:
        try:return checkout_rpc(service,{'checkout_id':identifier,'tenant_id':'tenant-a'},'create')['status']
        except GatewayDenied as error:return error.reason
    with ThreadPoolExecutor(max_workers=50) as pool:results=list(pool.map(attempt,range(50)))
    assert p.creates==1 and set(results)<={'AWAITING_PAYMENT','CHECKOUT_PENDING'}


def test_captured_webhook_binds_known_basket(fixture_store:Any)->None:
    """A captured event is only a trigger; trusted provider state must prove the binding."""
    from app.executor.main import process_webhook
    c,p,b,service=fixture_store;identifier=create(c,b).json()['checkout_id']
    service.settings.account_id='acc_fixture'
    service.refresh=lambda payment_id:None
    service.audit=lambda *args,**kwargs:'fixture-webhook-receipt'
    value={'account_id':'acc_fixture','event':'payment.captured','payload':{'payment':{'entity':{'id':'pay_storefixture','order_id':'order_storefixture'}}}}
    assert process_webhook(service,value,b'fixture-event','fixture-store-capture')['reason']=='WEBHOOK_APPLIED'
    with Session(c['engine']) as s:assert s.get(StoreCheckout,identifier).status=='PAID'


def test_selected_item_amount_cannot_exceed_purchased_value(fixture_store:Any)->None:
    """A shopper capability cannot request a different product or more than the purchased line."""
    c,p,b,_=fixture_store;identifier=create(c,b).json()['checkout_id'];path=b+'/checkouts/'+identifier
    c['client'].post(path+'/confirm',json=confirmation())
    for body in ({'product_id':'other-product','amount_paise':100,'text':'Refund'}, {'product_id':'fixture-product','amount_paise':10001,'text':'Refund'}):
        assert c['client'].post(path+'/support',json=body).json()['reason']=='INVALID_REFUND_AMOUNT'
    with Session(c['engine']) as s:assert s.scalar(select(func.count()).select_from(StoreSupportRequest))==0


def test_catalog_cli_explicit_idempotent_authoring(fixture_store:Any,monkeypatch:Any)->None:
    """The administrative CLI authors one real fixture record without startup seeding."""
    from app.commerce.catalog_cli import main
    c,p,b,_=fixture_store
    monkeypatch.setenv('DATABASE_URL',c['config'].database_url);monkeypatch.setenv('POLICY_FILE',str(c['policy_path']))
    monkeypatch.setattr('sys.argv',['catalog_cli','--operator','human','--name','CLI fixture','--category','Fixture category','--description','Fixture authored product','--price-paise','100'])
    main();main()
    with Session(c['engine']) as s:assert s.scalar(select(func.count()).select_from(StoreProduct).where(StoreProduct.name=='CLI fixture'))==1
