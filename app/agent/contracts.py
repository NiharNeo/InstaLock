"""Strict model outputs and bounded telemetry contracts."""
from typing import Annotated, Literal
from pydantic import Field
from app.core.canonical import PositiveInteger, _Contract


class RefundSuggestion(_Contract):
    """The sole model-call argument contract; extra fields always invalidate it."""
    payment_id: str = Field(min_length=1,max_length=128)
    amount_paise: PositiveInteger
    reason: str = Field(min_length=1,max_length=1000)


class CallReport(_Contract):
    """Metrics and fixed outcome codes only; no free-form response or ticket text."""
    ticket_id: str = Field(min_length=1,max_length=128)
    claim_token: str = Field(min_length=1,max_length=128)
    model: str = Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')
    input_tokens: Annotated[int,Field(strict=True,ge=0,le=9007199254740991)] | None
    output_tokens: Annotated[int,Field(strict=True,ge=0,le=9007199254740991)] | None
    total_tokens: Annotated[int,Field(strict=True,ge=0,le=9007199254740991)] | None
    latency_ms: Annotated[int,Field(strict=True,ge=0,le=9007199254740991)]
    outcome: Literal['INVALID_PROPOSAL','MODEL_ERROR','NO_PROPOSAL','PROPOSAL_SUBMITTED','POLICY_DENIED','SUBMISSION_UNCERTAIN']
