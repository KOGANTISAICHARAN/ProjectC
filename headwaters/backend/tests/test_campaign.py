"""Email DNA and campaign linkage.

The claim under test: the fingerprint links messages from one toolchain even
after the attacker rotates domains, addresses and IP ranges -- and does NOT link
unrelated messages that merely read alike.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.services.analysis import analyse
from app.services.campaign.dna import compute_dna, similarity
from app.services.campaign.linking import (
    LINK_THRESHOLD,
    MIN_AGREEING_LOCI,
    NON_CONTENT_LOCI,
    NON_CONTENT_THRESHOLD,
)

FIXTURES = Path(__file__).parent / "fixtures"
RELATED = ("bec", "campaign_meridian", "campaign_lantern")
UNRELATED = ("benign", "credential_phish")


def dna_for(name: str):
    return compute_dna(analyse((FIXTURES / f"{name}.eml").read_bytes()))


def links(a: str, b: str) -> tuple[bool, float, dict[str, float]]:
    score, per = similarity(dna_for(a), dna_for(b))
    gate = (
        sum(1 for v in per.values() if v >= 0.50) >= MIN_AGREEING_LOCI
        and max(per[k] for k in NON_CONTENT_LOCI) >= NON_CONTENT_THRESHOLD
    )
    return (gate and score >= LINK_THRESHOLD), score, per


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("bec", "campaign_meridian"),
        ("bec", "campaign_lantern"),
        ("campaign_meridian", "campaign_lantern"),
    ],
)
def test_same_toolchain_links_despite_rotated_infrastructure(a: str, b: str) -> None:
    linked, score, per = links(a, b)
    assert linked, f"{a}~{b} failed to link at {score:.3f}: {per}"
    assert per["m"] >= 0.95, "the tooling locus should match exactly"
    assert per["d"] <= 0.20, (
        "identity should NOT match -- these fixtures rotate domain and address, "
        "which is precisely what the tooling fingerprint has to survive"
    )


@pytest.mark.parametrize(
    ("a", "b"),
    [("bec", "benign"), ("bec", "credential_phish"), ("benign", "credential_phish")],
)
def test_unrelated_messages_do_not_link(a: str, b: str) -> None:
    linked, score, _ = links(a, b)
    assert not linked, f"{a}~{b} linked spuriously at {score:.3f}"


def test_separation_between_related_and_unrelated_is_wide() -> None:
    """The threshold must sit inside a real gap, not be tuned onto one case."""
    related = [links(a, b)[1] for a in RELATED for b in RELATED if a < b]
    unrelated = [links(a, b)[1] for a in (*RELATED, *UNRELATED) for b in UNRELATED if a != b]
    assert min(related) > max(unrelated) + 0.20, (
        f"separation too narrow: related min {min(related):.3f} "
        f"vs unrelated max {max(unrelated):.3f}"
    )


def test_content_alone_cannot_create_a_link() -> None:
    """All phishing sounds alike; shared phrasing must not form a campaign."""
    _, _, per = links("bec", "credential_phish")
    assert per["c"] > 0.3, "these do share social-engineering language"
    assert max(per[k] for k in NON_CONTENT_LOCI) < NON_CONTENT_THRESHOLD


def test_message_id_template_survives_a_different_timestamp() -> None:
    """A decimal timestamp is also valid hex; substituting digits first consumed
    it and split one generator's output into two templates."""
    bec = dna_for("bec").loci["m"]
    meridian = dna_for("campaign_meridian").loci["m"]
    assert bec["message_id_template"] == meridian["message_id_template"]


def test_boundary_shape_is_structural_not_character_class() -> None:
    bec = dna_for("bec").loci["m"]
    lantern = dna_for("campaign_lantern").loci["m"]
    assert bec["boundary_shape"] == lantern["boundary_shape"]


def test_header_emission_order_is_the_fingerprint() -> None:
    assert (
        dna_for("bec").loci["m"]["header_order_hash"]
        == (dna_for("campaign_lantern").loci["m"]["header_order_hash"])
    )
    assert (
        dna_for("bec").loci["m"]["header_order_hash"]
        != (dna_for("benign").loci["m"]["header_order_hash"])
    )


def test_barcode_is_six_bands() -> None:
    assert len(dna_for("bec").barcode) == 48
