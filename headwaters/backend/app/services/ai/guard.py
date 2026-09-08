"""Post-processing guards on model output.

The model is treated as an untrusted component that happens to be useful. Every
control here assumes it will occasionally produce something plausible and wrong.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.services.ai.schemas import Extraction

log = get_logger(__name__)

_WS = re.compile(r"\s+")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b[a-z0-9][a-z0-9-]{1,62}(?:\.[a-z]{2,24}){1,3}\b", re.IGNORECASE)
_HASH = re.compile(r"\b[0-9a-f]{32,64}\b", re.IGNORECASE)


@dataclass(slots=True)
class GuardReport:
    quotes_validated: int = 0
    quotes_dropped: int = 0
    facts_stripped: list[str] = field(default_factory=list)
    injection_detected: bool = False


def _normalise(text: str) -> str:
    return _WS.sub(" ", text).strip().lower()


def ground_quotes(extraction: Extraction, body: str) -> tuple[Extraction, GuardReport]:
    """Drop every finding whose quote is not verbatim in the message.

    This is the live hallucination control. A signal the model invented cannot
    reach the score, and the ratio of dropped to validated quotes is surfaced on
    the dashboard as a running measure of how much the model is confabulating.
    """
    report = GuardReport(injection_detected=extraction.prompt_injection_detected)
    haystack = _normalise(body)

    kept = []
    for signal in extraction.signals:
        if signal.quote and _normalise(signal.quote) in haystack:
            kept.append(signal)
            report.quotes_validated += 1
        else:
            report.quotes_dropped += 1
            log.warning(
                "ai.quote_ungrounded",
                signal=signal.type.value,
                quote=signal.quote[:80],
            )
    extraction.signals = kept

    for attr in ("impersonated_entity", "requested_action"):
        value = getattr(extraction, attr, None)
        if value is not None and _normalise(value.quote) not in haystack:
            setattr(extraction, attr, None)
            report.quotes_dropped += 1

    return extraction, report


def strip_invented_facts(
    extraction: Extraction, known_indicators: set[str], report: GuardReport
) -> Extraction:
    """Remove any IP, domain or hash the model produced that we did not already
    hold as an indicator.

    The model is given facts and may not introduce them. An address appearing
    only in model output is, by definition, not evidence.
    """
    known = {value.lower() for value in known_indicators}

    def scan(text: str, where: str) -> str:
        for pattern in (_IP, _DOMAIN, _HASH):
            for match in pattern.findall(text):
                if match.lower() not in known:
                    report.facts_stripped.append(f"{where}:{match}")
                    text = text.replace(match, "[redacted: not an established indicator]")
        return text

    if extraction.impersonated_entity:
        extraction.impersonated_entity.name = scan(
            extraction.impersonated_entity.name, "impersonated_entity"
        )
    if extraction.requested_action:
        extraction.requested_action.summary = scan(
            extraction.requested_action.summary, "requested_action"
        )

    if report.facts_stripped:
        log.warning("ai.facts_stripped", count=len(report.facts_stripped))
    return extraction
