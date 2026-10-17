"""Environment/secret-file configuration loaded only by the trusted executor."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat


def _secret(name: str) -> str:
    value,path = os.environ.get(name),os.environ.get(name+'_FILE')
    if bool(value) == bool(path):
        raise ValueError('configure exactly one source for '+name)
    if value:
        return value
    assert path is not None
    fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('protected regular secret file required')
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('secret too large')
    return raw.decode('utf-8').removesuffix('\n')


@dataclass(frozen=True)
class ExecutorSettings:
    """One test-mode merchant account mapped explicitly to one tenant per executor."""
    database_url: str
    policy_file: Path
    issuer: str
    tenant_id: str
    account_id: str
    key_id: str = field(repr=False)
    key_secret: str = field(repr=False)
    webhook_secret: str = field(repr=False)
    internal_token: str = field(repr=False)

    def __post_init__(self) -> None:
        if not re.fullmatch(r'rzp_test_[A-Za-z0-9]+',self.key_id):
            raise ValueError('only Razorpay test-mode keys are permitted')
        if not re.fullmatch(r'acc_[A-Za-z0-9]+',self.account_id):
            raise ValueError('real Razorpay account id required')
        if not self.database_url or not self.issuer or not self.tenant_id or len(self.tenant_id)>128:
            raise ValueError('explicit database, issuer and tenant required')
        if not self.key_secret or min(len(self.webhook_secret),len(self.internal_token)) < 32:
            raise ValueError('provider and strong webhook/internal secrets required')

    @classmethod
    def from_env(cls) -> 'ExecutorSettings':
        """Read executor-only configuration without fallback or live-mode credentials."""
        return cls(os.environ['DATABASE_URL'],Path(os.environ['POLICY_FILE']),os.environ['GRANT_ISSUER'],os.environ['EXECUTOR_TENANT_ID'],os.environ['RAZORPAY_ACCOUNT_ID'],_secret('RAZORPAY_KEY_ID'),_secret('RAZORPAY_KEY_SECRET'),_secret('RAZORPAY_WEBHOOK_SECRET'),_secret('EXECUTOR_AUTH_TOKEN'))
