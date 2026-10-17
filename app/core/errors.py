"""Stable gateway failures that abort the entire action transaction."""
from app.core.policy import Decision


class GatewayDenied(Exception):
    """Carry an explicit reason, fired rule, and safe HTTP status."""
    def __init__(self, reason: str, rule_id: str, status: int = 403):
        self.reason = reason
        self.rule_id = rule_id
        self.status = status
        super().__init__(reason)


def enforce(decision: Decision) -> None:
    """Abort unless the deterministic engine returned an explicit allow."""
    if not decision.allowed:
        raise GatewayDenied(decision.reason, decision.rule_id)
