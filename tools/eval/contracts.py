"""Strict secret-bearing capture files; persistence uses separate sanitized results."""
from typing import Any, Literal
from pydantic import Field, model_validator
from app.core.canonical import ProposedAction, _Contract


class Capture(_Contract):
    """An actual ticket/proposal/grant capture; never a generated business fixture."""
    name: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    role: Literal['fresh','expired','used','stale','different_tool']
    ticket_id: str = Field(min_length=1,max_length=128)
    proposal_id: str = Field(min_length=1,max_length=128)
    action: ProposedAction
    grant_token: str = Field(min_length=1,max_length=16384,repr=False)
    webhook_event_id: str | None = None
    other_tool_action: dict[str,Any] | None = None


class Plan(_Contract):
    """Real captures and explicit valid-refund workload; no generated financial data."""
    captures: list[Capture] = Field(min_length=1,max_length=200)
    base_id: str
    alternate_id: str
    foreign_payment_id: str
    valid_ids: list[str] = Field(min_length=40,max_length=40)
    concurrency_id: str

    @model_validator(mode='after')
    def _references(self) -> 'Plan':
        names=[c.name for c in self.captures]
        if len(set(names))!=len(names):
            raise ValueError('duplicate capture names')
        required={self.base_id,self.alternate_id,self.concurrency_id,*self.valid_ids}
        if not required.issubset(names):
            raise ValueError('unknown capture reference')
        if sum(c.role=='stale' for c in self.captures)<4:
            raise ValueError('four distinct pre-webhook stale approvals required')
        for role in ('expired','used','different_tool'):
            if not any(c.role==role for c in self.captures):
                raise ValueError('missing actual '+role+' capture')
        if next(c for c in self.captures if c.name==self.base_id).role!='fresh':
            raise ValueError('fresh base capture required')
        return self
