"""The analyst narrative.

A second call with a different job and a different risk profile. It runs AFTER
scoring, feeds nothing back, and is gated on the deterministic verdict -- most
reported mail is benign, and generating prose for it is spend with no reader.

Because it contributes nothing to the score, a hallucination here degrades a
paragraph rather than a verdict. That is what makes it safe to use a larger
model for it while the scored extraction stays on a tightly constrained one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

_PROMPTS = Path(__file__).parent / "prompts"

#: Below this score the narrative is templated rather than generated.
MIN_SCORE = 40

#: Phrases the narrative must never contain. The claim contract is enforced on
#: model output, not merely requested in the prompt -- a prompt is a preference,
#: a check is a control.
_FORBIDDEN = (
    "the attacker is located",
    "the attacker is in",
    "attacker is based",
    "travelled through",
    "traveled through",
    "physically located",
)


class Narrative(BaseModel):
    model_config = ConfigDict(extra="forbid")
    explanation: str = Field(description="3-5 sentences for a security analyst.")
    recommended_actions: list[str] = Field(default_factory=list)


@dataclass(slots=True)
class NarrativeResult:
    available: bool
    explanation: str
    recommended_actions: list[str] = field(default_factory=list)
    generated: bool = False
    model_id: str | None = None
    violations_stripped: list[str] = field(default_factory=list)
    unavailable_reason: str | None = None


def _templated(facts: dict[str, object]) -> NarrativeResult:
    """Deterministic fallback. Always available, never wrong."""
    band = str(facts.get("band", "unknown"))
    classification = str(facts.get("classification", "unknown")).replace("_", " ")
    raw_top = facts.get("top_findings")
    top: list[object] = list(raw_top) if isinstance(raw_top, list | tuple) else []
    reasons = "; ".join(str(t) for t in top[:3]) or "no significant findings"

    if band == "benign":
        return NarrativeResult(
            available=True,
            explanation=(
                f"No threat indicators of significance were identified. The message "
                f"was evaluated across the available signal groups and scored "
                f"{facts.get('score')} of 100."
            ),
            recommended_actions=["No action required."],
        )

    return NarrativeResult(
        available=True,
        explanation=(
            f"This message was classified as {classification} with a score of "
            f"{facts.get('score')} of 100 ({band}). The determining findings were: "
            f"{reasons}. Origin was reconstructed to the earliest externally observed "
            f"sending infrastructure with {facts.get('origin_confidence')}% confidence; "
            f"this identifies infrastructure, not a person."
        ),
        recommended_actions=[
            "Do not action any request in this message until verified out of band.",
            "Verify with the apparent sender using a contact from an internal "
            "directory, never one supplied in the message.",
            "Block the identified indicators at the mail gateway and the proxy.",
        ],
    )


def generate(db: Session, *, facts: dict[str, object]) -> NarrativeResult:
    """Generate the narrative, or return the templated one."""
    settings = get_settings()
    raw_score = facts.get("score")
    score = int(raw_score) if isinstance(raw_score, int | float | str) else 0

    if score < MIN_SCORE:
        # The cost gate. Most reported mail is benign; skipping generation for it
        # removes the large majority of narrative spend with no reader affected.
        result = _templated(facts)
        result.unavailable_reason = f"score {score} is below the generation threshold {MIN_SCORE}"
        return result

    if not settings.openai_api_key:
        result = _templated(facts)
        result.unavailable_reason = "OPENAI_API_KEY is not configured"
        return result

    payload = json.dumps(facts, sort_keys=True, default=str)
    key = hashlib.sha256(
        f"{settings.openai_model_narrative}\x00{settings.prompt_version}\x00{payload}".encode()
    ).hexdigest()

    cached = db.execute(text("SELECT payload FROM llm_cache WHERE key = :k"), {"k": key}).first()
    if cached is not None:
        data = Narrative.model_validate(cached[0])
        return _checked(data, settings.openai_model_narrative, generated=True)

    try:
        from openai import OpenAI

        client = OpenAI(api_key=settings.openai_api_key, timeout=25.0, max_retries=2)
        completion = client.beta.chat.completions.parse(
            model=settings.openai_model_narrative,
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": (_PROMPTS / "narrative_v1.txt").read_text(encoding="utf-8"),
                },
                {"role": "user", "content": payload},
            ],
            response_format=Narrative,
        )
        parsed = completion.choices[0].message.parsed
        if parsed is None:
            raise ValueError("model returned no parsed content")
    except Exception as exc:
        log.warning("ai.narrative_failed", error=str(exc)[:200])
        result = _templated(facts)
        result.unavailable_reason = f"{type(exc).__name__}: {str(exc)[:120]}"
        return result

    db.execute(
        text(
            "INSERT INTO llm_cache (key, model_id, prompt_version, payload) "
            "VALUES (:k, :m, :v, CAST(:p AS jsonb)) ON CONFLICT (key) DO NOTHING"
        ),
        {
            "k": key,
            "m": settings.openai_model_narrative,
            "v": settings.prompt_version,
            "p": json.dumps(parsed.model_dump(mode="json")),
        },
    )
    return _checked(parsed, settings.openai_model_narrative, generated=True)


def _checked(data: Narrative, model_id: str, *, generated: bool) -> NarrativeResult:
    """Enforce the claim contract on generated prose.

    A sentence that asserts an attacker's location is removed, not softened. The
    prompt asks the model not to write one; this makes sure it cannot ship if it
    does anyway.
    """
    violations: list[str] = []
    explanation = data.explanation
    lowered = explanation.lower()

    for phrase in _FORBIDDEN:
        if phrase in lowered:
            violations.append(phrase)
            sentences = [s for s in explanation.split(". ") if phrase not in s.lower()]
            explanation = ". ".join(sentences)
            lowered = explanation.lower()

    if violations:
        log.warning("ai.narrative_claim_violation", phrases=violations)
        explanation += (
            " [A statement asserting the operator's physical location was removed: "
            "the evidence does not support such a claim.]"
        )

    return NarrativeResult(
        available=True,
        explanation=explanation.strip(),
        recommended_actions=data.recommended_actions[:5],
        generated=generated,
        model_id=model_id,
        violations_stripped=violations,
    )
