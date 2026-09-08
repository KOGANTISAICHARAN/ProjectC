"""Authentication re-verification and network attribution.

The distinctions asserted here are the ones that stop the system making false
accusations: an unverifiable signature is not a failed one, and a network is not
a person.
"""

from __future__ import annotations

from pathlib import Path

from app.models.enums import AuthResult
from app.services.forensics.verify import aligned, verify_dkim
from app.services.intel.dns import registrable_domain
from app.services.intel.geo import datasets_present, lookup

FIXTURES = Path(__file__).parent / "fixtures"


# ------------------------------------------------------ organisational domain
def test_public_suffix_list_beats_the_last_two_labels_heuristic() -> None:
    """DMARC alignment is computed on the organisational domain, so the
    heuristic this replaces produced genuinely wrong verdicts on multi-part
    suffixes -- not merely imprecise ones."""
    assert registrable_domain("news.bbc.co.uk") == "bbc.co.uk"
    assert registrable_domain("shop.example.com.au") == "example.com.au"
    assert registrable_domain("mail.kaverifs.com") == "kaverifs.com"


def test_alignment_is_relaxed_by_default() -> None:
    assert aligned("mail.kaverifs.com", "kaverifs.com") is True
    assert aligned("kaverifs-corp.com", "kaverifs.com") is False


def test_strict_alignment_requires_an_exact_match() -> None:
    assert aligned("mail.kaverifs.com", "kaverifs.com", mode="s") is False
    assert aligned("kaverifs.com", "kaverifs.com", mode="s") is True


def test_alignment_is_undecidable_without_both_domains() -> None:
    assert aligned(None, "kaverifs.com") is None
    assert aligned("kaverifs.com", None) is None


# ------------------------------------------------------------------- DKIM
def test_unfetchable_selector_key_is_indeterminate_not_failed() -> None:
    """The single most important distinction in this module.

    dkimpy returns False both for "the signature is invalid" and for "the key
    could not be fetched". Those mean opposite things: the first accuses the
    sender, the second says the evidence expired. Key rotation is routine, so
    conflating them produces false accusations against legitimate senders.
    """
    result = verify_dkim((FIXTURES / "bec.eml").read_bytes())
    assert result.result is AuthResult.INDETERMINATE
    assert result.selector == "selector1"
    assert result.d_domain == "kaverifs-corp.com"
    assert result.caveat is not None
    assert "NOT a failed one" in result.caveat


def test_signed_header_list_is_captured() -> None:
    """Which headers a signature covers determines what it actually protects."""
    result = verify_dkim((FIXTURES / "bec.eml").read_bytes())
    assert "from" in result.signed_headers
    assert "subject" in result.signed_headers


def test_absent_signature_reports_none_not_fail() -> None:
    result = verify_dkim((FIXTURES / "benign.eml").read_bytes())
    assert result.result is AuthResult.NONE
    assert result.caveat is not None and "no DKIM-Signature" in result.caveat


def test_verification_never_raises_on_malformed_input() -> None:
    assert verify_dkim(b"not an email at all").result is AuthResult.NONE
    assert verify_dkim(b"").result is AuthResult.NONE


# --------------------------------------------------------- network attribution
def test_private_addresses_carry_no_attribution() -> None:
    assert lookup("10.0.0.14").source == "local"
    assert lookup("127.0.0.1").source == "local"


def test_documentation_ranges_are_labelled_not_given_a_country() -> None:
    """The synthetic corpus must never be presented as having a real location."""
    info = lookup("203.0.113.41")
    assert info.country is None
    assert info.network_type == "documentation"
    assert "documentation range" in (info.org or "")


def test_every_answer_carries_its_source() -> None:
    """A reader must always be able to tell a geolocation lookup from a fallback
    table. Presenting them identically is how a confident wrong country ends up
    in a report."""
    for ip in ("40.107.1.2", "203.0.113.41", "10.0.0.14", "192.0.2.99"):
        assert lookup(ip).source
    assert lookup("1.2.3.4").source == "unavailable"


def test_invalid_input_is_handled() -> None:
    assert lookup(None).source == "unavailable"
    assert lookup("not-an-ip").source == "unavailable"


def test_datasets_present_reports_what_is_installed() -> None:
    present = datasets_present()
    assert set(present) == {"geolite2_asn", "geolite2_country", "fallback_table"}
    assert present["fallback_table"] is True


def test_no_city_field_exists() -> None:
    """City-level precision is not defensible for datacentre ranges, so it is
    not modelled at all rather than being modelled and discouraged."""
    assert not hasattr(lookup("40.107.1.2"), "city")
