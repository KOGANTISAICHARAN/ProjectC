"""Explainable risk fusion.

Never an average of model confidences. Eight groups, each producing a normalised
score in [0,1] from named sub-signals, combined with published weights and three
structural controls:

1. **Corroboration gate** -- a Critical verdict needs two independent groups
   above threshold, at least one deterministic. This is the direct answer to
   "how does one weak signal produce a critical verdict?": it cannot.
2. **AI ceiling** -- the content group can never alone push a case past High.
3. **Legitimacy dampener** -- aligned DMARC on an established domain reduces the
   score, unless display-name spoofing overrides it.

Every point traces to a Finding row carrying its rule id and its evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.logging import get_logger
from app.models.enums import Band, Classification, FindingGroup, Severity

log = get_logger(__name__)

_WEIGHTS_PATH = Path(__file__).with_name("weights.yaml")

#: Severity -> the fraction of a group's weight one finding can claim.
SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.55,
    Severity.HIGH: 0.80,
    Severity.CRITICAL: 1.0,
}


@dataclass(slots=True)
class RawFinding:
    """A detection, before it has been weighted into a score.

    Carries two descriptions on purpose. ``plain`` is one sentence a
    non-specialist can act on; ``detail`` is the precise technical account that
    has to withstand an expert challenge. Writing only the second means nobody
    reads it; writing only the first means it cannot be defended. The UI leads
    with ``plain`` and keeps ``detail`` one click away.
    """

    group: FindingGroup
    rule_id: str
    severity: Severity
    title: str
    detail: str | None = None
    #: One sentence, no jargon, active voice. What a reader should conclude.
    plain: str | None = None
    evidence_ref: str | None = None
    evidence_quote: str | None = None
    mitre_technique: str | None = None
    confidence: float | None = None


@dataclass(slots=True)
class ScoredFinding:
    raw: RawFinding
    contribution: float


@dataclass(slots=True)
class FusionResult:
    score: int
    band: Band
    classification: Classification
    group_scores: dict[str, float]
    group_contributions: dict[str, float]
    scored: list[ScoredFinding]
    controls_applied: list[str] = field(default_factory=list)
    data_completeness: int = 0
    weights_version: str = "v1"


@lru_cache(maxsize=1)
def load_weights() -> dict[str, Any]:
    with _WEIGHTS_PATH.open("r", encoding="utf-8") as handle:
        return dict(yaml.safe_load(handle))


def fuse(findings: list[RawFinding], *, groups_evaluated: set[FindingGroup]) -> FusionResult:
    """Combine findings into an explainable 0-100 score.

    ``groups_evaluated`` is the set of groups that actually ran -- NOT the set
    that produced a finding. The distinction is the difference between "checked
    and found clean" and "never checked", and conflating them silently deflates
    every score: a case analysed with threat intelligence offline would score
    lower than the identical case with it on, purely because two groups
    contributed zero out of a denominator that assumed they had run.

    The score is therefore normalised over the weight that was actually
    available, and ``data_completeness`` reports how much that was.
    """
    config = load_weights()
    weights: dict[str, int] = config["groups"]
    controls: dict[str, Any] = config["controls"]
    deterministic: set[str] = set(config["deterministic_groups"])

    # --- per-group normalised score ---------------------------------------
    # The strongest finding sets the floor; additional findings add with
    # diminishing returns, so ten medium signals never outrank one critical one.
    by_group: dict[str, list[RawFinding]] = {}
    for finding in findings:
        by_group.setdefault(finding.group.value, []).append(finding)

    group_scores: dict[str, float] = {}
    for group, items in by_group.items():
        magnitudes = sorted((SEVERITY_WEIGHT[f.severity] for f in items), reverse=True)
        score = magnitudes[0] if magnitudes else 0.0
        for extra in magnitudes[1:]:
            score += extra * (1.0 - score) * 0.5
        group_scores[group] = round(min(1.0, score), 4)

    # --- weighted sum, normalised over EVALUATED groups only ---------------
    # A group that never ran must not be scored as if it ran and found nothing.
    # Counting Band B groups as zero deflates every offline analysis and makes
    # the score depend on which providers happened to be reachable.
    evaluated = {g.value for g in groups_evaluated}
    available_weight = sum(w for g, w in weights.items() if g in evaluated) or sum(weights.values())

    contributions = {
        group: round(group_scores.get(group, 0.0) * weight, 2)
        for group, weight in weights.items()
        if group in evaluated
    }
    raw_total = sum(contributions.values())
    base = raw_total / available_weight * 100.0

    applied: list[str] = []
    if available_weight < sum(weights.values()):
        missing = sorted(set(weights) - evaluated)
        applied.append(
            f"normalised over {available_weight}/{sum(weights.values())} available weight; "
            f"not evaluated: {', '.join(missing)}"
        )

    # --- control 2: AI ceiling ---------------------------------------------
    # Content is a modifier of risk, never a source of it. A case may pass the
    # ceiling only when the DETERMINISTIC evidence alone already does, scored on
    # the same normalised basis -- otherwise the control would fire differently
    # depending on which Band B providers were reachable.
    content_weight = weights.get("content", 0) if "content" in evaluated else 0
    deterministic_weight = max(1, available_weight - content_weight)
    non_content = (raw_total - contributions.get("content", 0.0)) / deterministic_weight * 100.0

    if non_content < controls["ai_ceiling"] and base > controls["ai_ceiling"]:
        base = float(controls["ai_ceiling"])
        applied.append(
            f"ai_ceiling: deterministic evidence alone scores {non_content:.0f}, below "
            f"{controls['ai_ceiling']}; social-engineering signals cannot carry a case "
            f"past that on their own"
        )

    # --- control 1: corroboration gate -------------------------------------
    gate = controls["corroboration"]
    strong = [g for g, s in group_scores.items() if s >= gate["group_threshold"]]
    strong_deterministic = [g for g in strong if g in deterministic]

    corroborated = (
        len(strong) >= gate["required_groups"]
        and len(strong_deterministic) >= gate["deterministic_required"]
    )
    if not corroborated and base > gate["cap_without_corroboration"]:
        base = float(gate["cap_without_corroboration"])
        applied.append(
            f"corroboration_gate: capped at {gate['cap_without_corroboration']} -- "
            f"a Critical verdict needs {gate['required_groups']} independent groups "
            f">= {gate['group_threshold']}, at least "
            f"{gate['deterministic_required']} deterministic "
            f"(found {len(strong)} / {len(strong_deterministic)})"
        )
    elif corroborated:
        applied.append(
            f"corroboration_gate: satisfied by {len(strong)} groups ({', '.join(sorted(strong))})"
        )

    # --- control 3: legitimacy dampener ------------------------------------
    rule_ids = {f.rule_id for f in findings}
    if "AUTH_DMARC_ALIGNED_ESTABLISHED" in rule_ids and not (
        rule_ids & {"IDENT_PROTECTED_DISPLAY_NAME", "IDENT_LOOKALIKE_DOMAIN"}
    ):
        base += controls["legitimacy_dampener"]
        applied.append(
            f"legitimacy_dampener: {controls['legitimacy_dampener']} "
            "(DMARC aligned to an established domain, no impersonation signal)"
        )

    score = max(0, min(100, round(base)))
    band = _band_for(score, config["bands"])

    scored = [
        ScoredFinding(
            raw=f,
            contribution=round(
                SEVERITY_WEIGHT[f.severity]
                * weights.get(f.group.value, 0)
                / max(1, len(by_group.get(f.group.value, []))),
                2,
            ),
        )
        for f in findings
    ]

    return FusionResult(
        score=score,
        band=band,
        classification=_classify(rule_ids, group_scores, band),
        group_scores=group_scores,
        group_contributions=contributions,
        scored=scored,
        controls_applied=applied,
        data_completeness=len(groups_evaluated),
        weights_version=str(config["version"]),
    )


def _band_for(score: int, bands: dict[str, list[int]]) -> Band:
    for name, (low, high) in bands.items():
        if low <= score <= high:
            return Band(name)
    return Band.BENIGN


def _classify(rule_ids: set[str], group_scores: dict[str, float], band: Band) -> Classification:
    """Derived from WHICH groups fired, not from the score.

    A score of 88 driven by attachments is a different animal from an 88 driven
    by identity, and the label has to say so -- an analyst triages the label
    before they read the number.
    """
    if band is Band.BENIGN:
        return Classification.BENIGN

    impersonation = bool(rule_ids & {"IDENT_PROTECTED_DISPLAY_NAME", "IDENT_LOOKALIKE_DOMAIN"})
    has_attachment_risk = group_scores.get("attachment", 0.0) >= 0.7
    has_credential_url = "URL_CREDENTIAL_LANDING" in rule_ids

    # Order matters and encodes analyst triage priority. BEC is the label only
    # when the message actually asks for a financial action -- otherwise an
    # impersonated sender pointing at a sign-in page is credential phishing, and
    # calling it BEC would send the analyst down the wrong response playbook.
    financial = "CONTENT_FINANCIAL" in rule_ids

    if impersonation and financial and group_scores.get("authentication", 0.0) >= 0.5:
        return Classification.BEC
    if has_credential_url:
        return Classification.CREDENTIAL_PHISHING
    if has_attachment_risk:
        return Classification.MALWARE_DELIVERY
    if impersonation:
        return Classification.IMPERSONATION
    if band in (Band.HIGH, Band.CRITICAL):
        return Classification.PHISHING
    return Classification.UNKNOWN
