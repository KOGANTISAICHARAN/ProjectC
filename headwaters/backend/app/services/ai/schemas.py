"""The contract with the model.

Closed enumerations throughout. The model cannot return a value outside these
sets, so anything that reaches the scoring engine is already a member of a
vocabulary the engine understands -- there is no "unknown attack type" branch to
get wrong, because an unknown value is rejected before it exists.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Level(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


#: Rubric buckets map to numbers HERE, in code -- never in the model's output.
#: A model asked for "urgency: 94%" produces generated text, not a calibrated
#: probability. Asking for a bucket and converting it ourselves means the
#: percentage on screen is arithmetic we own and can defend.
LEVEL_SCORE: dict[Level, float] = {
    Level.NONE: 0.0,
    Level.LOW: 0.25,
    Level.MEDIUM: 0.55,
    Level.HIGH: 0.80,
    Level.EXTREME: 1.0,
}


class SignalType(StrEnum):
    URGENCY = "urgency"
    AUTHORITY_PRESSURE = "authority_pressure"
    SECRECY = "secrecy"
    FINANCIAL_REQUEST = "financial_request"
    CREDENTIAL_REQUEST = "credential_request"
    PROCESS_DEVIATION = "process_deviation"
    FEAR = "fear"
    REWARD = "reward"


class AttackType(StrEnum):
    BEC_EXECUTIVE_IMPERSONATION = "bec_executive_impersonation"
    CREDENTIAL_PHISHING = "credential_phishing"
    INVOICE_FRAUD = "invoice_fraud"
    MALWARE_DELIVERY = "malware_delivery"
    VENDOR_COMPROMISE = "vendor_compromise"
    EXTORTION = "extortion"
    BENIGN = "benign"
    OTHER = "other"


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: SignalType
    level: Level
    rubric: list[str] = Field(
        default_factory=list,
        description="Which rubric criteria matched. Justifies the level.",
    )
    quote: str = Field(
        description="A VERBATIM substring of the message body. Validated after "
        "the call; a finding whose quote cannot be located is discarded."
    )


class Entity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    role: str | None = None
    quote: str


class RequestedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str
    quote: str


class Extraction(BaseModel):
    """Social-engineering intent only. No facts, no verdict, no score."""

    model_config = ConfigDict(extra="forbid")

    attack_type: AttackType
    confidence: Level
    impersonated_entity: Entity | None = None
    requested_action: RequestedAction | None = None
    signals: list[Signal] = Field(default_factory=list)
    process_deviation: bool = False
    prompt_injection_detected: bool = False
    injection_quote: str | None = None
    template_skeleton: str = ""
