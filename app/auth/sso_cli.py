"""Trusted administration: invite an actual verified business operator to OIDC login."""
import argparse
import os
from sqlalchemy.orm import Session
from app.auth.oidc import https_endpoint
from intentlock.db import engine_for,SSOIdentity,User,KeyRegistry


def main() -> None:
    """Map a real email to an existing human and owned signing key; never create business data."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--email',required=True)
    parser.add_argument('--operator-id',required=True)
    parser.add_argument('--kid',required=True)
    parser.add_argument('--issuer',required=True)
    args=parser.parse_args()
    email=args.email.strip().casefold()
    if not 3<=len(email)<=254 or '@' not in email or any(c.isspace() for c in email):raise ValueError('actual email required')
    issuer=https_endpoint(args.issuer).rstrip('/')
    with Session(engine_for(os.environ['DATABASE_URL'])) as session,session.begin():
        user=session.get(User,args.operator_id);key=session.get(KeyRegistry,args.kid)
        if user is None or not user.active or key is None or not key.active or key.operator_id!=user.id or key.tenant_id!=user.tenant_id:raise ValueError('active operator and owned key required')
        session.add(SSOIdentity(email=email,user_id=user.id,signing_kid=key.kid,issuer=issuer,subject=None,active=True))
    print('SSO invitation registered; identity must authenticate with the configured provider.')


if __name__=='__main__':main()
