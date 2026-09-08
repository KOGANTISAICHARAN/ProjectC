"""OpenAI integration.

Two calls with different jobs and different risk profiles:

**extract** runs on every case and feeds the score, so it is the most tightly
constrained thing in the system: strict schema, closed enumerations, verbatim
quotes, facts injected rather than generated, capped at 12 of 100 points.

**narrative** writes prose for a human, is gated on the deterministic score, and
feeds nothing back. Its failure mode is a worse paragraph, not a wrong verdict --
which is why it may use a larger model without weakening the security argument.

Both are cached by ``sha256(model || prompt_version || normalised_input)``. A hit
returns in milliseconds with no network, which is simultaneously the cost
control, the offline guarantee, and the reason the same message always yields the
same analysis: the reproducibility a forensic pipeline needs and a temperature
setting alone cannot provide.

With no API key configured the whole layer reports itself unavailable and the
case completes at reduced data completeness. It never blocks, and it never
fabricates.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.ai.guard import GuardReport, ground_quotes, strip_invented_facts
from app.services.ai.schemas import Extraction

log = get_logger(__name__)

_PROMPTS = Path(__file__).parent / "prompts"

#: Gate for the expensive call. Most reported mail is benign, so scoring the
#: narrative behind the deterministic verdict removes roughly three quarters of
#: the spend with no visible loss.
NARRATIVE_MIN_SCORE = 40


@dataclass(slots=True)
class AiResult:
    available: bool
    extraction: Extraction | None
    guard: GuardReport
    model_id: str
    prompt_version: str
    input_sha256: str
    output_sha256: str
    latency_ms: int
    cached: bool
    unavailable_reason: str | None = None


def _prompt(name: str) -> str:
    return (_PROMPTS / name).read_text(encoding="utf-8")


def _cache_key(model: str, version: str, payload: str) -> str:
    return hashlib.sha256(f"{model}\x00{version}\x00{payload}".encode()).hexdigest()


def _cache_get(db: Session, key: str) -> dict[str, Any] | None:
    row = db.execute(text("SELECT payload FROM llm_cache WHERE key = :k"), {"k": key}).first()
    if row is None:
        return None
    db.execute(
        text("UPDATE llm_cache SET hits = hits + 1, last_hit_at = now() WHERE key = :k"),
        {"k": key},
    )
    return dict(row[0])


def _cache_put(db: Session, key: str, model: str, version: str, payload: dict[str, Any]) -> None:
    db.execute(
        text(
            """
            INSERT INTO llm_cache (key, model_id, prompt_version, payload)
            VALUES (:k, :m, :v, CAST(:p AS jsonb))
            ON CONFLICT (key) DO NOTHING
            """
        ),
        {"k": key, "m": model, "v": version, "p": json.dumps(payload)},
    )


def analyse_intent(
    db: Session,
    *,
    subject: str | None,
    body: str,
    established_facts: dict[str, object],
    known_indicators: set[str],
) -> AiResult:
    """Run the extraction call, or report cleanly why it could not run."""
    settings = get_settings()
    version = settings.prompt_version
    model = settings.openai_model_extract
    guard = GuardReport()

    user_payload = json.dumps(
        {
            "established_facts": established_facts,
            "subject": subject or "",
            "email_body": body[:12000],
        },
        sort_keys=True,
    )
    key = _cache_key(model, version, user_payload)
    input_hash = hashlib.sha256(user_payload.encode()).hexdigest()

    cached = _cache_get(db, key)
    if cached is not None:
        extraction = Extraction.model_validate(cached)
        extraction, guard = ground_quotes(extraction, body)
        extraction = strip_invented_facts(extraction, known_indicators, guard)
        return AiResult(
            available=True,
            extraction=extraction,
            guard=guard,
            model_id=model,
            prompt_version=version,
            input_sha256=input_hash,
            output_sha256=hashlib.sha256(json.dumps(cached, sort_keys=True).encode()).hexdigest(),
            latency_ms=0,
            cached=True,
        )

    if not settings.openai_api_key:
        return AiResult(
            available=False,
            extraction=None,
            guard=guard,
            model_id=model,
            prompt_version=version,
            input_sha256=input_hash,
            output_sha256="",
            latency_ms=0,
            cached=False,
            unavailable_reason=(
                "OPENAI_API_KEY is not configured. The content signal group is "
                "reported as not evaluated; the deterministic verdict is unaffected."
            ),
        )

    started = time.perf_counter()
    try:
        from openai import OpenAI

        client = OpenAI(api_key=settings.openai_api_key, timeout=20.0, max_retries=2)
        completion = client.beta.chat.completions.parse(
            model=model,
            temperature=0,
            messages=[
                {"role": "system", "content": _prompt("extract_v1.txt")},
                {"role": "user", "content": user_payload},
            ],
            response_format=Extraction,
        )
        parsed = completion.choices[0].message.parsed
        if parsed is None:
            raise ValueError("model returned no parsed content")
    except Exception as exc:
        # A provider failure marks the group unavailable. It never blocks the
        # case and never substitutes a guess.
        log.warning("ai.extract_failed", error=str(exc)[:200])
        return AiResult(
            available=False,
            extraction=None,
            guard=guard,
            model_id=model,
            prompt_version=version,
            input_sha256=input_hash,
            output_sha256="",
            latency_ms=int((time.perf_counter() - started) * 1000),
            cached=False,
            unavailable_reason=f"{type(exc).__name__}: {str(exc)[:160]}",
        )

    latency = int((time.perf_counter() - started) * 1000)
    payload = parsed.model_dump(mode="json")
    _cache_put(db, key, model, version, payload)

    extraction, guard = ground_quotes(parsed, body)
    extraction = strip_invented_facts(extraction, known_indicators, guard)

    log.info(
        "ai.extract",
        model=model,
        latency_ms=latency,
        quotes_validated=guard.quotes_validated,
        quotes_dropped=guard.quotes_dropped,
        injection=guard.injection_detected,
    )
    return AiResult(
        available=True,
        extraction=extraction,
        guard=guard,
        model_id=model,
        prompt_version=version,
        input_sha256=input_hash,
        output_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        latency_ms=latency,
        cached=False,
    )


def persist(db: Session, *, org_id: uuid.UUID, case_id: uuid.UUID, result: AiResult) -> None:
    """Record which analytic produced these findings, so a reviewer can re-run it."""
    if not result.available or result.extraction is None:
        return
    db.execute(
        text(
            """
            INSERT INTO ai_analysis (org_id, case_id, call_kind, model_id, prompt_version,
                input_sha256, output_sha256, payload, quotes_validated, quotes_dropped,
                prompt_injection_detected, latency_ms, cached)
            VALUES (:o, :c, 'extract', :m, :v, :ih, :oh, CAST(:p AS jsonb),
                    :qv, :qd, :inj, :lat, :cached)
            """
        ),
        {
            "o": str(org_id),
            "c": str(case_id),
            "m": result.model_id,
            "v": result.prompt_version,
            "ih": result.input_sha256,
            "oh": result.output_sha256,
            "p": json.dumps(result.extraction.model_dump(mode="json")),
            "qv": result.guard.quotes_validated,
            "qd": result.guard.quotes_dropped,
            "inj": result.guard.injection_detected,
            "lat": result.latency_ms,
            "cached": result.cached,
        },
    )
