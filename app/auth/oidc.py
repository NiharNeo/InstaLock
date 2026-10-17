"""Invite-only OIDC authorization code login with PKCE and verified identity claims."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode,urlsplit,quote
import httpx
import jwt
from fastapi import APIRouter,Request
from fastapi.responses import JSONResponse,RedirectResponse
from sqlalchemy import select,update
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from app.auth.service import SESSION_COOKIE,check_origin,provision_session,secret_hash
from app.core.dispatch import load_dispatch_cipher
from app.core.errors import GatewayDenied
from app.executor.config import _secret
from app.intake.service import rate_limit
from intentlock.db import SSOAttempt,SSOIdentity

router=APIRouter()
STATE_COOKIE='intentlock_oidc'


def configured() -> bool:
    """Advertise only an explicitly configured deployment identity provider."""
    return bool(os.environ.get('OIDC_ISSUER') and os.environ.get('OIDC_CLIENT_ID') and (os.environ.get('OIDC_CLIENT_SECRET') or os.environ.get('OIDC_CLIENT_SECRET_FILE')))


def https_endpoint(value: Any) -> str:
    """Accept only administrator/provider supplied HTTPS endpoints without credentials."""
    if not isinstance(value,str) or len(value)>2048:
        raise ValueError('invalid identity endpoint')
    parsed=urlsplit(value)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('HTTPS identity endpoint required')
    return value


def provider_document(client: httpx.Client) -> dict[str,Any]:
    """Fetch bounded discovery from the fixed administrator-configured issuer."""
    issuer=https_endpoint(os.environ['OIDC_ISSUER']).rstrip('/')
    document=fetch_document(client,issuer+'/.well-known/openid-configuration')
    if document.get('issuer')!=issuer:
        raise ValueError('issuer discovery mismatch')
    for field in ('authorization_endpoint','token_endpoint','jwks_uri'):
        https_endpoint(document[field])
    return document


def fetch_document(client: httpx.Client,url: str) -> dict[str,Any]:
    """Read bounded HTTPS provider JSON without redirects or unbounded response bodies."""
    with client.stream('GET',https_endpoint(url)) as response:
        response.raise_for_status();raw=bytearray()
        for chunk in response.iter_bytes():
            raw.extend(chunk)
            if len(raw)>131072:raise ValueError('oversized identity response')
    result=parse_identity_json(bytes(raw))
    if not isinstance(result,dict):raise ValueError('identity document must be an object')
    return result


def parse_identity_json(raw: bytes) -> Any:
    """Allow protocol boolean fields while retaining duplicate, Unicode and number checks.

    OIDC discovery legitimately uses boolean capability flags. ProposedAction's
    parser intentionally forbids booleans and must not be relaxed for this protocol.
    """
    from app.core.canonical import _pairs,_reject_number,_check_string,_check_tree
    result=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_float=_reject_number,parse_constant=_reject_number)
    def check(value: Any) -> None:
        if type(value) is bool:return
        if isinstance(value,dict):
            for key,child in value.items():_check_string(key);check(child)
        elif isinstance(value,list):
            for child in value:check(child)
        else:_check_tree(value)
    check(result)
    return result


def validate_id_token(token: str,keys: dict[str,Any],issuer: str,client_id: str,nonce: str) -> dict[str,Any]:
    """Pin RS256, issuer/audience/time/nonce and verified email; ignore token URLs."""
    if not isinstance(token,str) or len(token)>16384:raise ValueError('invalid token')
    header=jwt.get_unverified_header(token)
    if header.get('alg')!='RS256' or not isinstance(header.get('kid'),str):raise ValueError('algorithm not allowed')
    matches=[key for key in keys.get('keys',[]) if key.get('kid')==header['kid'] and key.get('kty')=='RSA' and key.get('use','sig')=='sig' and key.get('alg','RS256')=='RS256']
    if len(matches)!=1:raise ValueError('unknown identity signing key')
    claims=jwt.decode(token,jwt.PyJWK.from_dict(matches[0]).key,algorithms=['RS256'],issuer=issuer,audience=client_id,leeway=30,options={'require':['iss','aud','exp','iat','sub','nonce','email','email_verified']})
    if any(type(claims[k]) is not int for k in ('exp','iat')):raise ValueError('integer identity timestamps required')
    if type(claims['email_verified']) is not bool or not claims['email_verified'] or not isinstance(claims['sub'],str) or not 1<=len(claims['sub'])<=255:
        raise ValueError('verified identity required')
    if not isinstance(claims['nonce'],str) or not hmac.compare_digest(claims['nonce'],nonce):raise ValueError('nonce mismatch')
    if claims.get('azp',client_id)!=client_id or (isinstance(claims['aud'],list) and len(claims['aud'])>1 and claims.get('azp')!=client_id):raise ValueError('authorized party mismatch')
    if not isinstance(claims['email'],str) or not 3<=len(claims['email'])<=254 or '@' not in claims['email']:raise ValueError('invalid email')
    return claims


def bind_identity(session: Session,claims: dict[str,Any],issuer: str) -> tuple[str,str]:
    """Bind a verified subject only to a pre-invited active human, never create tenants."""
    email=claims['email'].casefold()
    session.execute(update(SSOIdentity).where(SSOIdentity.email==email).values(active=SSOIdentity.active))
    row=session.get(SSOIdentity,email)
    if row is None or not row.active or row.issuer!=issuer or (row.subject is not None and row.subject!=claims['sub']):
        raise GatewayDenied('SSO_ACCESS_DENIED','auth.sso_invitation',403)
    row.subject=claims['sub']
    from intentlock.db import User
    user=session.get(User,row.user_id)
    if user is None:raise GatewayDenied('SSO_ACCESS_DENIED','auth.sso_invitation',403)
    session.info.update(receipt_tenant=user.tenant_id,receipt_actor=user.id)
    return provision_session(session,row.user_id,row.signing_kid,28800)


@router.get('/v1/auth/providers')
async def providers(request: Request) -> JSONResponse:
    """Expose the deployment's canonical URL and explicitly published real storefront."""
    gateway=request.app.state.gateway
    storefront=None
    identifier=os.environ.get('PUBLIC_STORE_CHANNEL','')
    if identifier:
        from intentlock.db import SupportChannel
        try:
            def read() -> str | None:
                with Session(gateway.engine) as session:
                    channel=session.get(SupportChannel,identifier)
                    if channel is not None and channel.active:
                        return gateway.settings.origin+'/store/'+quote(channel.id,safe='')
                    return None
            storefront=await run_in_threadpool(read)
        except Exception:
            return await denied(request,'PUBLIC_METADATA_UNAVAILABLE',503)
    return JSONResponse({'sso_enabled':configured(),'label':os.environ.get('OIDC_DISPLAY_NAME','Company SSO')[:80],'workspace_url':gateway.settings.origin,'storefront_url':storefront})


async def denied(request: Request,reason: str,status: int=403) -> JSONResponse:
    """Audit SSO denial without retaining passwords, codes, or identity tokens."""
    body,code=await run_in_threadpool(request.app.state.gateway.deny,b'',GatewayDenied(reason,'auth.sso',status))
    messages={'SSO_ACCESS_DENIED':'This Google account is not invited to this workspace. Sign in again and choose your invited Google email.','SSO_LOGIN_FAILED':'Sign-in could not be completed. Start a new sign-in attempt; do not refresh the callback URL.'}
    if reason in messages:body['message']=messages[reason]
    response=JSONResponse(body,status_code=code)
    response.delete_cookie(STATE_COOKIE,path='/v1/auth',samesite='lax')
    return response


@router.get('/v1/auth/start')
async def start(request: Request) -> Any:
    """Create one-use browser state and redirect only to the configured identity provider."""
    gateway=request.app.state.gateway
    try:
        if not configured():return await denied(request,'SSO_NOT_CONFIGURED',503)
        check_origin(request,gateway.settings.origin)
        if request.query_params or request.headers.get('authorization'):raise ValueError('invalid login request')
        def begin() -> tuple[str,str]:
            state,browser,nonce,verifier=(secrets.token_urlsafe(48) for _ in range(4))
            with httpx.Client(timeout=10,follow_redirects=False) as client:document=provider_document(client)
            with Session(gateway.engine) as session,session.begin():
                if request.client is None:raise ValueError('client unavailable')
                rate_limit(session,request.client.host)
                session.add(SSOAttempt(id=secret_hash(state),browser_hash=secret_hash(browser),nonce=nonce,verifier_ciphertext=load_dispatch_cipher().encrypt(verifier.encode()).decode(),expires_at=int(time.time())+600,used=False))
                gateway.audit(session,b'','SSO_STARTED','auth.sso',True)
            challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            return document['authorization_endpoint']+'?'+urlencode({'client_id':os.environ['OIDC_CLIENT_ID'],'redirect_uri':gateway.settings.origin+'/v1/auth/callback','response_type':'code','scope':'openid email profile','prompt':'select_account','state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'}),browser
        url,browser=await run_in_threadpool(begin)
        response=RedirectResponse(url,status_code=302)
        response.set_cookie(STATE_COOKIE,browser,max_age=600,path='/v1/auth',httponly=True,secure=gateway.settings.origin.startswith('https://'),samesite='lax')
        return response
    except GatewayDenied as error:return await denied(request,error.reason,error.status)
    except Exception:return await denied(request,'SSO_UNAVAILABLE',503)


@router.get('/v1/auth/callback')
async def callback(request: Request) -> Any:
    """Consume state once, exchange code server-side, and create a scoped HttpOnly session."""
    gateway=request.app.state.gateway
    try:
        if not configured():return await denied(request,'SSO_NOT_CONFIGURED',503)
        query=request.query_params
        # Authorization codes must not remain in server access-log request targets.
        request.scope['query_string']=b''
        if set(query)-{'state','code','scope','authuser','prompt','iss'} or any(len(query.getlist(k))!=1 for k in query) or not 1<=len(query.get('state',''))<=128 or not 1<=len(query.get('code',''))<=4096:
            raise ValueError('invalid callback')
        if query.get('iss',os.environ['OIDC_ISSUER'].rstrip('/'))!=os.environ['OIDC_ISSUER'].rstrip('/'):raise ValueError('callback issuer mismatch')
        if sum(part.strip().split('=',1)[0]==STATE_COOKIE for part in request.headers.get('cookie','').split(';'))!=1:raise ValueError('ambiguous browser state')
        def finish() -> tuple[str,str]:
            with Session(gateway.engine) as session,session.begin():
                row=session.get(SSOAttempt,secret_hash(query['state']))
                if row is None or row.used or row.expires_at<=int(time.time()) or not hmac.compare_digest(row.browser_hash,secret_hash(request.cookies.get(STATE_COOKIE,''))):raise ValueError('invalid state')
                consumed=session.execute(update(SSOAttempt).where(SSOAttempt.id==row.id,SSOAttempt.used.is_(False),SSOAttempt.expires_at>int(time.time())).values(used=True))
                if consumed.rowcount!=1:raise ValueError('state already consumed')
                verifier=load_dispatch_cipher().decrypt(row.verifier_ciphertext.encode()).decode();nonce=row.nonce
                row.verifier_ciphertext=''
            with httpx.Client(timeout=10,follow_redirects=False) as client:
                document=provider_document(client)
                response=client.post(document['token_endpoint'],data={'grant_type':'authorization_code','code':query['code'],'redirect_uri':gateway.settings.origin+'/v1/auth/callback','client_id':os.environ['OIDC_CLIENT_ID'],'client_secret':_secret('OIDC_CLIENT_SECRET'),'code_verifier':verifier})
                response.raise_for_status()
                if len(response.content)>131072:raise ValueError('oversized response')
                token=parse_identity_json(response.content)['id_token'];keys=fetch_document(client,document['jwks_uri'])
            claims=validate_id_token(token,keys,document['issuer'],os.environ['OIDC_CLIENT_ID'],nonce)
            with Session(gateway.engine) as session,session.begin():
                token,csrf=bind_identity(session,claims,document['issuer'])
                gateway.audit(session,b'','SSO_AUTHENTICATED','auth.sso',True)
            return token,csrf
        token,_=await run_in_threadpool(finish)
        response=RedirectResponse(gateway.settings.origin+'/',status_code=303)
        response.set_cookie(SESSION_COOKIE,token,max_age=28800,path='/v1',httponly=True,secure=gateway.settings.origin.startswith('https://'),samesite='strict')
        response.delete_cookie(STATE_COOKIE,path='/v1/auth',samesite='lax')
        return response
    except GatewayDenied as error:return await denied(request,error.reason,error.status)
    except Exception:return await denied(request,'SSO_LOGIN_FAILED',403)
