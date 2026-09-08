"""The analyst narrative and its claim-contract enforcement."""

from __future__ import annotations

from app.services.ai.narrative import MIN_SCORE, Narrative, _checked, _templated


def test_templated_narrative_is_always_available() -> None:
    """The fallback must never fail: a case without a narrative is a case an
    analyst has to reconstruct by hand."""
    result = _templated(
        {
            "band": "critical",
            "classification": "bec",
            "score": 86,
            "origin_confidence": 65,
            "top_findings": ["lookalike domain"],
        }
    )
    assert result.available
    assert result.explanation
    assert result.recommended_actions


def test_benign_narrative_recommends_no_action() -> None:
    result = _templated({"band": "benign", "classification": "benign", "score": 0})
    assert "No action required." in result.recommended_actions


def test_generation_is_gated_on_the_deterministic_score() -> None:
    """Most reported mail is benign; generating prose for it is spend with no
    reader."""
    assert MIN_SCORE > 0


def test_claim_violations_are_removed_from_generated_prose() -> None:
    """The prompt asks the model not to assert a location. This makes sure it
    cannot ship if it does anyway -- a prompt is a preference, a check is a
    control."""
    data = Narrative(
        explanation=(
            "This is a business email compromise attempt. The attacker is located "
            "in Singapore. The sender domain was registered recently."
        ),
        recommended_actions=["Verify by phone."],
    )
    result = _checked(data, "test-model", generated=True)
    assert "attacker is located" not in result.explanation.lower()
    assert result.violations_stripped
    assert "removed" in result.explanation


def test_clean_prose_passes_through_unchanged() -> None:
    data = Narrative(
        explanation="The sending domain was registered six days before delivery.",
        recommended_actions=["Block the domain."],
    )
    result = _checked(data, "test-model", generated=True)
    assert result.explanation == data.explanation
    assert not result.violations_stripped


def test_recommended_actions_are_bounded() -> None:
    data = Narrative(explanation="ok", recommended_actions=[f"a{i}" for i in range(20)])
    assert len(_checked(data, "m", generated=True).recommended_actions) <= 5
