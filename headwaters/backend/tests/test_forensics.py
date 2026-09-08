"""The forensics engine.

Pure functions over bytes: no database, no HTTP, no network. That is the point
of keeping `services/` free of FastAPI -- the most valuable code in the project
is also the cheapest to test.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.models.enums import Band, Classification, IpClass, Severity, TrustState
from app.services.analysis import analyse
from app.services.forensics import parser, received
from app.services.forensics.origin import reconstruct_origin

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> bytes:
    return (FIXTURES / f"{name}.eml").read_bytes()


# ------------------------------------------------------------------ parsing
def test_header_order_is_preserved() -> None:
    """Emission order is Email DNA locus M. Collapsing headers to a map would
    destroy the strongest fingerprint we have of the sending toolchain."""
    parsed = parser.parse_email(load("bec"))
    names = [n.lower() for n, _ in parsed.headers]
    assert names.index("received") < names.index("from")
    assert len(parsed.get_all("received")) == 5


def test_duplicate_headers_are_retained_not_deduplicated() -> None:
    """Two From headers is an RFC violation and a real attack; a parser that
    keeps only the first cannot detect it."""
    parsed = parser.parse_email(load("malformed"))
    assert len(parsed.get_all("From")) == 2


def test_malformed_message_parses_without_raising() -> None:
    """Hostile mail is deliberately non-conforming. Failing to parse is a denial
    of service, not a safe default."""
    parsed = parser.parse_email(load("malformed"))
    assert parsed.raw_sha256
    assert parsed.defects, "defects should be recorded, not swallowed"


def test_crlf_is_stripped_from_header_values() -> None:
    """A header value that can re-open header parsing downstream is an injection
    primitive."""
    raw = b"From: a@example.test\r\nSubject: ok\r\n\r\nbody\r\n"
    parsed = parser.parse_email(raw)
    assert all("\n" not in v and "\r" not in v for _, v in parsed.headers)


def test_archives_are_hashed_but_never_expanded() -> None:
    parsed = parser.parse_email(load("bec"))
    assert parsed.attachments
    for attachment in parsed.attachments:
        assert len(attachment.sha256) == 64


# -------------------------------------------------------- received chain
def test_peer_address_comes_from_the_from_clause_not_the_by_clause() -> None:
    """Searching the whole header finds the RECEIVER's own address, which would
    make every hop appear to originate from the host that received it."""
    parsed = parser.parse_email(load("bec"))
    hops = received.parse_received_chain(parsed.get_all("Received"))
    assert hops[2].observed_ip == "203.0.113.41"
    assert hops[2].by_host is not None
    assert "outlook.com" in hops[2].by_host


def test_ipv6_compressed_form_is_extracted() -> None:
    parsed = parser.parse_email(load("bec"))
    hops = received.parse_received_chain(parsed.get_all("Received"))
    assert hops[1].observed_ip == "2001:db8:2::17"


def test_documentation_ranges_are_not_treated_as_private() -> None:
    """RFC 5737/3849 ranges are reserved, but they stand in for PUBLIC
    addresses. Python's ipaddress reports them private, which would make every
    synthetic fixture unanalysable."""
    assert received.classify_ip("203.0.113.41") is IpClass.PUBLIC
    assert received.classify_ip("2001:db8:2::17") is IpClass.PUBLIC
    assert received.classify_ip("10.0.0.14") is IpClass.PRIVATE
    assert received.classify_ip("127.0.0.1") is IpClass.LOOPBACK


def test_ipv4_mapped_ipv6_is_unwrapped() -> None:
    assert received.normalise_ip("::ffff:203.0.113.9") == "203.0.113.9"


# ------------------------------------------------------------------ origin
def test_trust_boundary_lands_at_the_last_recognised_provider() -> None:
    parsed = parser.parse_email(load("bec"))
    hops = received.parse_received_chain(parsed.get_all("Received"))
    origin = reconstruct_origin(hops, org_domains=("kaverifs.com",))

    assert origin.boundary_seq == 2
    assert origin.feos_ip == "203.0.113.41", "FEOS must be the peer the boundary hop observed"
    assert origin.hop_trust[0] is TrustState.VOUCHED
    assert origin.hop_trust[2] is TrustState.BOUNDARY
    assert origin.hop_trust[3] is TrustState.ASSERTED


def test_forged_timestamp_is_detected_below_the_boundary() -> None:
    parsed = parser.parse_email(load("bec"))
    hops = received.parse_received_chain(parsed.get_all("Received"))
    origin = reconstruct_origin(hops, org_domains=("kaverifs.com",))
    assert "timestamp_not_monotonic" in origin.flags


def test_internal_private_hop_above_the_boundary_is_not_an_anomaly() -> None:
    """The provider-to-gateway handoff is private and completely normal. Flagging
    it would fire on virtually every legitimate enterprise email."""
    parsed = parser.parse_email(load("bec"))
    hops = received.parse_received_chain(parsed.get_all("Received"))
    origin = reconstruct_origin(hops, org_domains=("kaverifs.com",))
    assert "private_ip_after_public" not in origin.flags


def test_confidence_is_never_certain() -> None:
    parsed = parser.parse_email(load("bec"))
    hops = received.parse_received_chain(parsed.get_all("Received"))
    origin = reconstruct_origin(hops, org_domains=("kaverifs.com",))
    assert 5 <= origin.confidence <= 95
    assert sum(origin.breakdown.values()) != 0


def test_claim_text_never_asserts_attacker_location() -> None:
    """docs/CLAIM_CONTRACT.md is normative. Any output contradicting it is a bug."""
    for name in ("bec", "credential_phish", "benign"):
        claim = analyse(load(name)).origin.claim_text.lower()
        assert "the attacker is" not in claim
        assert "attacker is located" not in claim
        assert "travelled through" not in claim


def test_no_received_headers_refuses_to_answer() -> None:
    origin = reconstruct_origin([], org_domains=("kaverifs.com",))
    assert origin.feos_ip is None
    assert origin.confidence <= 15
    assert "no sending infrastructure can be identified" in origin.claim_text


# ------------------------------------------------------- authentication
def test_injected_authentication_results_is_detected_and_discarded() -> None:
    """The BEC fixture carries a second A-R header forged by the sender."""
    result = analyse(load("bec"))
    assert result.auth.forged_pass_detected
    assert result.auth.trusted_authserv == "kaverifs.com"
    assert any(f.rule_id == "AUTH_INJECTED_RESULTS" for f in result.findings)


# ------------------------------------------------------------------ scoring
def test_bec_fixture_scores_critical() -> None:
    result = analyse(load("bec"))
    assert result.fusion.band is Band.CRITICAL
    assert result.fusion.classification is Classification.BEC
    assert result.fusion.score >= 85


def test_benign_newsletter_scores_benign() -> None:
    """The false-positive guard. A divergent Reply-To and a bulk sender must not
    be enough to flag legitimate mail -- a judge will upload their own."""
    result = analyse(load("benign"))
    assert result.fusion.band is Band.BENIGN
    assert result.fusion.classification is Classification.BENIGN


def test_credential_phish_is_not_labelled_bec() -> None:
    """Classification drives the analyst's response playbook, so an impersonated
    sender pointing at a sign-in page must not be filed as wire fraud."""
    result = analyse(load("credential_phish"))
    assert result.fusion.classification is Classification.CREDENTIAL_PHISHING


def test_ungraded_groups_do_not_deflate_the_score() -> None:
    """Band B groups never ran. Scoring them as zero is indistinguishable from
    'checked and found clean' and silently penalises every offline analysis."""
    result = analyse(load("bec"))
    assert result.fusion.data_completeness == 6
    assert any("normalised over 82/100" in c for c in result.fusion.controls_applied)


@pytest.mark.parametrize("name", ["bec", "credential_phish", "benign", "malformed"])
def test_every_fixture_analyses_without_raising(name: str) -> None:
    result = analyse(load(name))
    assert 0 <= result.fusion.score <= 100


# ------------------------------------------- email service provider senders --
def test_esp_sent_mail_is_not_flagged_for_unaligned_spf() -> None:
    """Regression, found by analysing a real GroupMe password-reset email.

    GroupMe sends through Amazon SES, so SPF passes for ``amazonses.com`` (the
    provider's bounce domain) while DKIM passes for ``groupmemailer.com``. DMARC
    passes overall, because DMARC needs only ONE identifier to align.

    Flagging the unaligned SPF as HIGH marked the standard configuration of
    every SES / SendGrid / Mailchimp sender as suspicious. The real message
    scored 47 -- "likely malicious" -- for being a perfectly ordinary password
    reset.
    """
    result = analyse(load("legit_password_reset"))
    rule_ids = {f.rule_id for f in result.findings}

    assert "AUTH_SPF_PASS_UNALIGNED" not in rule_ids
    assert result.fusion.band is Band.BENIGN


def test_subdomain_bounce_address_is_not_return_path_divergence() -> None:
    """``mail.example.com`` bouncing for ``example.com`` is a subdomain, not a
    divergence. Comparing raw strings fired on correctly configured senders."""
    result = analyse(load("campaign_meridian"))
    assert "IDENT_RETURN_PATH_DIVERGENT" not in {f.rule_id for f in result.findings}


def test_credential_link_is_downgraded_not_suppressed_when_aligned() -> None:
    """DMARC alignment proves the sender CONTROLS the domain, never that the
    domain is trustworthy -- an attacker who registers their own and configures
    it correctly aligns too.

    So the signal is weighted down, not switched off. Suppressing it entirely
    made two attack fixtures score benign.
    """
    legit = analyse(load("legit_password_reset"))
    attack = analyse(load("campaign_lantern"))

    legit_url = [f for f in legit.findings if f.rule_id == "URL_CREDENTIAL_LANDING"]
    attack_url = [f for f in attack.findings if f.rule_id == "URL_CREDENTIAL_LANDING"]

    assert legit_url, "the finding must still be recorded, not erased"
    assert legit_url[0].severity is Severity.LOW
    assert attack_url, "an attacker's own aligned domain must not go unrecorded"
    assert attack.fusion.band is not Band.BENIGN


def test_attack_fixtures_still_outrank_legitimate_mail() -> None:
    """The property the whole false-positive fix has to preserve."""
    legit = analyse(load("legit_password_reset")).fusion.score
    newsletter = analyse(load("benign")).fusion.score
    for attack in ("bec", "credential_phish", "campaign_meridian", "campaign_lantern"):
        assert analyse(load(attack)).fusion.score > max(legit, newsletter)
