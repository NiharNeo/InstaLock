"""Environment-only credentials and versioned policy configuration."""
import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    """Immutable policy snapshot for one gateway process."""
    database_url: str
    agent_token: str
    operator_token: str
    agent_tenant: str
    policy_version: str
    max_refund_paise: int
    max_grant_seconds: int

    @classmethod
    def from_env(cls) -> 'Settings':
        """Fail startup if credentials or policy are missing or ambiguous."""
        settings = cls(os.environ['DATABASE_URL'], os.environ['AGENT_TOKEN'], os.environ['OPERATOR_TOKEN'], os.environ['AGENT_TENANT'], os.environ['POLICY_VERSION'], int(os.environ['MAX_REFUND_PAISE']), int(os.environ['MAX_GRANT_SECONDS']))
        if min(len(settings.agent_token), len(settings.operator_token)) < 32 or settings.agent_token == settings.operator_token:
            raise ValueError('distinct tokens of at least 32 characters required')
        if not settings.agent_tenant or not settings.policy_version or not 0 < settings.max_refund_paise <= 9007199254740991 or settings.max_grant_seconds <= 0:
            raise ValueError('invalid policy')
        return settings
