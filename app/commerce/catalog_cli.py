"""Explicit catalog administration; no products are created by application startup."""
import argparse,hashlib,time,os
from pathlib import Path
from uuid import uuid4
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.commerce.contracts import ProductInput
from app.core.receipts import append_receipt,load_receipt_key
from app.core.policy import PolicyEngine
from intentlock.db import engine_for,User,StoreProduct


def main() -> None:
    """Insert a deliberately authored product for an existing active operator's tenant."""
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ('operator','name','category','description'):parser.add_argument('--'+field,required=True)
    parser.add_argument('--price-paise',required=True,type=int)
    args=parser.parse_args();body=ProductInput(name=args.name,category=args.category,description=args.description,price_paise=args.price_paise)
    engine=engine_for(os.environ['DATABASE_URL']);load_receipt_key();policy=PolicyEngine.load(Path(os.environ['POLICY_FILE']))
    with Session(engine) as s,s.begin():
        user=s.get(User,args.operator)
        if user is None or not user.active:raise ValueError('existing active operator required')
        existing=s.scalar(select(StoreProduct).where(StoreProduct.tenant_id==user.tenant_id,StoreProduct.name==body.name))
        if existing:
            if any(getattr(existing,k)!=v for k,v in body.model_dump().items()):raise ValueError('existing product differs; edit requires separate review')
            print('Existing authored product retained');return
        identifier=uuid4().hex;s.add(StoreProduct(id=identifier,tenant_id=user.tenant_id,**body.model_dump(),active=True,created_at=int(time.time())))
        append_receipt(s,tenant_id=user.tenant_id,actor_id=user.id,id=str(uuid4()),timestamp=int(time.time()),allowed=True,reason='CATALOG_PRODUCT_CREATED',rule_id='commerce.catalog_admin',policy_version=policy.policy_version,input_hash=hashlib.sha256(identifier.encode()).hexdigest(),action_digest=None,request_id=identifier,refund_id=None)
    print('Authored catalog product saved')


if __name__=='__main__':main()
