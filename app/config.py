"""Startup-only public configuration for the v1 gateway."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class GatewaySettings:
    """Environment configuration; policy versions come only from policy bytes."""
    database_url: str
    policy_file: Path
    issuer: str
    origin: str
    executor_url: str | None = None
    executor_token: str | None = field(default=None,repr=False)

    def __post_init__(self) -> None:
        if bool(self.executor_url)!=bool(self.executor_token):
            raise ValueError('executor URL and token required together')
        if self.executor_url:
            endpoint=urlsplit(self.executor_url)
            if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path not in {'','/'} or not endpoint.hostname or (endpoint.scheme!='https' and not (endpoint.scheme=='http' and endpoint.hostname in {'executor','localhost','127.0.0.1','::1'})) or len(self.executor_token or '')<32:
                raise ValueError('protected executor address and strong token required')
        parsed = urlsplit(self.origin)
        if not self.database_url or not self.issuer or len(self.issuer) > 128:
            raise ValueError('database URL and bounded issuer required')
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path or not parsed.hostname:
            raise ValueError('APP_ORIGIN must be an exact origin without a path')
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in {'localhost','127.0.0.1','::1'}):
            raise ValueError('HTTPS required outside loopback')

    @classmethod
    def from_env(cls) -> GatewaySettings:
        """Load required environment values without fallback credentials or tenants."""
        return cls(os.environ['DATABASE_URL'],Path(os.environ['POLICY_FILE']),os.environ['GRANT_ISSUER'],os.environ['APP_ORIGIN'],os.environ['EXECUTOR_URL'],os.environ['EXECUTOR_AUTH_TOKEN'])
