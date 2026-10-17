"""Prepare isolated local Docker configuration from existing protected service settings.

This imports no business fixtures and issues no grants or provider calls. SQLite
backup copies the actual ledger. Volume initialization refuses to overwrite data.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
from uuid import uuid4
from typing import Any
import yaml
from sqlalchemy.engine import make_url


def read_protected(path: Path) -> bytes:
    """Read a bounded regular protected file without following the final symlink."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('PROTECTED_LOCAL_FILE_REQUIRED')
        value=stream.read(262145)
    if len(value)>262144:
        raise ValueError('LOCAL_CONFIG_TOO_LARGE')
    return value


def write_protected(path: Path,raw: bytes) -> None:
    """Write only technical configuration/security material, refusing symlink targets."""
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.is_symlink():
        raise ValueError('SYMLINK_OUTPUT_NOT_ALLOWED')
    temporary=path.with_name(path.name+'.'+str(uuid4())+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def service_environment(path: Path) -> dict[str,str]:
    """Require explicit string environment values from actual local service configuration."""
    data=json.loads(read_protected(path))
    if type(data) is not dict or not all(type(k) is str and type(v) is str for k,v in data.items()):
        raise ValueError('STRING_SERVICE_ENVIRONMENT_REQUIRED')
    return data


def secret(values: dict[str,str],name: str) -> bytes:
    """Resolve exactly one existing environment or protected-file source."""
    inline,pem,path=values.get(name),values.get(name+'_PEM'),values.get(name+'_FILE')
    if sum(bool(value) for value in (inline,pem,path))!=1:
        raise ValueError('EXACTLY_ONE_SECRET_SOURCE_REQUIRED')
    return (inline or pem).encode() if inline or pem else read_protected(Path(path or ''))


def snapshot(runtime: Path) -> Path:
    """Take an online-consistent backup of the actual SQLite ledger, never an empty stand-in."""
    if (runtime/'docker'/'active.json').exists():
        raise ValueError('NATIVE_LEDGER_RETIRED_USE_DOCKER_BACKUP')
    values=service_environment(runtime/'gateway-env.json')
    url=make_url(values['DATABASE_URL'])
    if url.drivername!='sqlite' or not url.database or not Path(url.database).is_file():
        raise ValueError('EXISTING_SQLITE_LEDGER_REQUIRED')
    destination=runtime/'docker'/'ledger.sqlite'
    temporary=destination.with_suffix('.sqlite.tmp')
    write_protected(temporary,b'')
    with sqlite3.connect(Path(url.database).resolve().as_uri()+'?mode=ro',uri=True) as source,sqlite3.connect(temporary) as target:
        source.backup(target)
        if target.execute('PRAGMA integrity_check').fetchone()!=('ok',):
            raise ValueError('LEDGER_BACKUP_INVALID')
    temporary.replace(destination)
    return destination


def prepare(runtime: Path) -> Path:
    """Generate a private Compose file with per-service credentials and separate secret volumes."""
    gateway=service_environment(runtime/'gateway-env.json')
    executor=service_environment(runtime/'executor-env.json')
    agent=service_environment(runtime/'agent-env.json')
    project=Path(__file__).resolve().parents[2]
    target=runtime/'docker';target.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not secret(executor,'RAZORPAY_KEY_ID').decode().startswith('rzp_test_'):
        raise ValueError('TEST_MODE_REQUIRED')
    if Path(gateway['POLICY_FILE']).resolve()!=Path(executor['POLICY_FILE']).resolve():
        raise ValueError('MATCHING_POLICY_REQUIRED')
    policy=read_protected(Path(gateway['POLICY_FILE']))
    write_protected(target/'policy'/'refunds.yaml',policy)
    # Policy is non-secret; the enclosing runtime directory remains mode 0700 on host.
    (target/'policy').chmod(0o755)
    (target/'policy'/'refunds.yaml').chmod(0o444)
    # Copy actual existing key material into staging, never into a build context.
    receipt=secret(gateway,'RECEIPT_PRIVATE_KEY')
    if receipt!=secret(executor,'RECEIPT_PRIVATE_KEY'):
        raise ValueError('MATCHING_RECEIPT_KEY_REQUIRED')
    for name,value in {'receipt.pem':receipt,'operator.pem':secret(gateway,'GRANT_PRIVATE_KEY'),'dispatch.key':read_protected(Path(gateway['DISPATCH_KEY_FILE']))}.items():
        write_protected(target/'gateway'/name,value)
    for name,value in {'receipt.pem':receipt,'razorpay-key-id':secret(executor,'RAZORPAY_KEY_ID'),'razorpay-key-secret':secret(executor,'RAZORPAY_KEY_SECRET'),'webhook-secret':secret(executor,'RAZORPAY_WEBHOOK_SECRET')}.items():
        write_protected(target/'executor'/name,value)
    common={'DATABASE_URL':'sqlite:////data/intentlock.db','POLICY_FILE':'/app/policies/refunds.yaml','GRANT_ISSUER':gateway['GRANT_ISSUER'],'EXECUTOR_AUTH_TOKEN':gateway['EXECUTOR_AUTH_TOKEN'],'RECEIPT_PRIVATE_KEY_FILE':'/run/secrets/receipt.pem'}
    if executor['EXECUTOR_AUTH_TOKEN']!=gateway['EXECUTOR_AUTH_TOKEN']:
        raise ValueError('MATCHING_EXECUTOR_TOKEN_REQUIRED')
    gw={**common,'APP_ORIGIN':gateway.get('DEPLOYMENT_ORIGIN','http://127.0.0.1:8080'),'EXECUTOR_URL':'http://executor:8001','GRANT_PRIVATE_KEY_FILE':'/run/secrets/operator.pem','GRANT_PRIVATE_KEY_PASSWORD':gateway.get('GRANT_PRIVATE_KEY_PASSWORD',''),'DISPATCH_KEY_FILE':'/run/secrets/dispatch.key','INTAKE_RATE_SECRET':gateway['INTAKE_RATE_SECRET'],'SESSION_CSRF_SECRET':gateway['SESSION_CSRF_SECRET']}
    if gateway.get('PUBLIC_STORE_CHANNEL'):
        gw['PUBLIC_STORE_CHANNEL']=gateway['PUBLIC_STORE_CHANNEL']
    if gateway.get('STORE_PUBLIC_ORIGIN'):
        gw['STORE_PUBLIC_ORIGIN']=gateway['STORE_PUBLIC_ORIGIN']
    if gateway.get('OIDC_ISSUER'):
        if not gateway.get('OIDC_CLIENT_ID'):
            raise ValueError('OIDC_CLIENT_ID_REQUIRED')
        write_protected(target/'gateway'/'oidc-client-secret',secret(gateway,'OIDC_CLIENT_SECRET'))
        gw.update(OIDC_ISSUER=gateway['OIDC_ISSUER'],OIDC_CLIENT_ID=gateway['OIDC_CLIENT_ID'],OIDC_CLIENT_SECRET_FILE='/run/secrets/oidc-client-secret',OIDC_DISPLAY_NAME=gateway.get('OIDC_DISPLAY_NAME','Company SSO'))
    ex={**common,**{k:executor[k] for k in ('EXECUTOR_TENANT_ID','RAZORPAY_ACCOUNT_ID')},'RAZORPAY_KEY_ID_FILE':'/run/secrets/razorpay-key-id','RAZORPAY_KEY_SECRET_FILE':'/run/secrets/razorpay-key-secret','RAZORPAY_WEBHOOK_SECRET_FILE':'/run/secrets/webhook-secret'}
    ag={k:agent[k] for k in ('AGENT_SERVICE_KEY','GEMINI_API_KEY','GEMINI_MODEL')};ag['GATEWAY_URL']='http://gateway:8000'
    policy_mount=str(target/'policy')+':/app/policies:ro'
    def trusted(environment: dict[str,str],volume: str,command: list[str]) -> dict[str,Any]:
        return {'image':'intentlock-local-api:latest','environment':environment,'volumes':['ledger:/data',policy_mount,volume+':/run/secrets:ro'],'command':command,'restart':'unless-stopped','security_opt':['no-new-privileges:true'],'cap_drop':['ALL'],'depends_on':{'migrate':{'condition':'service_completed_successfully'}}}
    services={'migrate':{'image':'intentlock-local-api:latest','environment':{'DATABASE_URL':common['DATABASE_URL']},'volumes':['ledger:/data'],'command':['alembic','upgrade','head'],'security_opt':['no-new-privileges:true'],'cap_drop':['ALL']},'executor':trusted(ex,'executor_secrets',['uvicorn','app.executor.main:app','--host','0.0.0.0','--port','8001']),'gateway':trusted(gw,'gateway_secrets',['uvicorn','app.main:app','--host','0.0.0.0','--port','8000']),'reconciler':trusted(ex,'executor_secrets',['python','-m','app.executor.reconcile']),'agent':{'image':'intentlock-local-agent:latest','environment':ag,'read_only':True,'restart':'unless-stopped','security_opt':['no-new-privileges:true'],'cap_drop':['ALL'],'depends_on':{'gateway':{'condition':'service_healthy'}}},'web':{'image':'intentlock-local-web:latest','ports':['127.0.0.1:8080:8080'],'restart':'unless-stopped','security_opt':['no-new-privileges:true'],'cap_drop':['ALL'],'depends_on':{'gateway':{'condition':'service_healthy'},'executor':{'condition':'service_healthy'}}}}
    for name,port in (('gateway',8000),('executor',8001)):
        services[name]['healthcheck']={'test':['CMD','python','-c',f"import urllib.request; urllib.request.urlopen('http://127.0.0.1:{port}/health/ready',timeout=4).read()"],'interval':'15s','timeout':'5s','retries':3,'start_period':'20s'}
    services['gateway']['depends_on']['executor']={'condition':'service_healthy'}
    services['reconciler']['depends_on']['executor']={'condition':'service_healthy'}
    services['web']['healthcheck']={'test':['CMD','wget','-q','-O','/dev/null','http://127.0.0.1:8080/health/ready'],'interval':'15s','timeout':'5s','retries':3}
    spec={'name':'intentlock-local','services':services,'volumes':{'ledger':{'name':'intentlock_local_ledger','external':True},'gateway_secrets':{'name':'intentlock_local_gateway_secrets','external':True},'executor_secrets':{'name':'intentlock_local_executor_secrets','external':True}}}
    destination=target/'compose.yaml';write_protected(destination,yaml.safe_dump(spec,sort_keys=False).encode())
    return destination


def backup_docker(runtime: Path) -> Path:
    """Stream a consistent live-volume backup to a protected host file without exposing contents."""
    config=runtime/'docker'/'compose.yaml'
    read_protected(config)
    destination=runtime/'backups'/('ledger-'+str(uuid4())+'.sqlite')
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    program="""import os,sqlite3,tempfile,shutil,sys
from sqlalchemy.engine import make_url
url=make_url(os.environ['DATABASE_URL'])
if url.drivername!='sqlite' or not url.database:raise SystemExit(2)
with tempfile.TemporaryDirectory() as directory:
 path=directory+'/ledger.sqlite'
 with sqlite3.connect('file:'+url.database+'?mode=ro',uri=True) as source,sqlite3.connect(path) as target:
  source.backup(target)
  if target.execute('PRAGMA integrity_check').fetchone()!=('ok',):raise SystemExit(3)
 with open(path,'rb') as stream:shutil.copyfileobj(stream,sys.stdout.buffer)
"""
    fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:
            result=subprocess.run(['docker','compose','-f',str(config),'exec','-T','gateway','python','-c',program],stdout=stream,stderr=subprocess.PIPE,timeout=120,check=False)
        if result.returncode:
            raise ValueError('LIVE_BACKUP_FAILED')
        with sqlite3.connect(destination.resolve().as_uri()+'?mode=ro',uri=True) as connection:
            if connection.execute('PRAGMA integrity_check').fetchone()!=('ok',):
                raise ValueError('LIVE_BACKUP_INVALID')
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


def main() -> None:
    """Prepare private local settings or snapshot the actual ledger before Docker cutover."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['prepare','snapshot','backup'])
    parser.add_argument('--runtime-dir',type=Path,default=Path('.runtime'))
    args=parser.parse_args()
    try:
        actions={'prepare':prepare,'snapshot':snapshot,'backup':backup_docker}
        result=actions[args.command](args.runtime_dir.resolve())
    except Exception:
        raise SystemExit('LOCAL_STACK_PREPARATION_FAILED: inspect protected sources and schema; no secrets printed.') from None
    print('Prepared protected local artifact:',result)


if __name__=='__main__':
    main()
