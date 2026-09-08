"""Independent re-verification of email authentication.

WHAT CAN AND CANNOT BE RE-CHECKED
---------------------------------
**DKIM can.** It is a cryptographic signature over the headers and body, so it
can be verified offline against the selector's published key -- with one
important caveat: if that key has since been rotated, the signature becomes
*indeterminate*, not *failed*. Reporting a rotated key as a failure is a forensic
error that would accuse a legitimate sender.

**SPF cannot, authoritatively.** It is evaluated by the receiving MTA at the
moment of delivery, against DNS as it existed then. A present-day re-check tells
you what the record says *now*. That is corroborating context, and it is labelled
as such rather than presented as the result.

**DMARC policy can be fetched now**, and the *impersonated* domain's policy is
the more interesting lookup: "the domain being imitated publishes p=reject, and
this message did not come from it" is a far stronger statement than any pass or
fail on the sender's own domain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.logging import get_logger
from app.models.enums import AuthResult
from app.services.intel.dns import registrable_domain, txt

log = get_logger(__name__)

_SPF_ALL = re.compile(r"(?P<qualifier>[-~?+])?all\b")


@dataclass(frozen=True, slots=True)
class DkimVerification:
    result: AuthResult
    selector: str | None
    d_domain: str | None
    signed_headers: tuple[str, ...]
    body_length_limited: bool
    caveat: str | None


@dataclass(frozen=True, slots=True)
class DmarcPolicy:
    domain: str
    found: bool
    policy: str | None
    subdomain_policy: str | None
    alignment_spf: str
    alignment_dkim: str
    raw: str | None
    resolved: bool


@dataclass(frozen=True, slots=True)
class SpfRecord:
    domain: str
    found: bool
    raw: str | None
    all_qualifier: str | None
    permissive: bool
    resolved: bool


def verify_dkim(raw_message: bytes) -> DkimVerification:
    """Re-verify the DKIM signature against the published selector key."""
    selector = d_domain = None
    signed: tuple[str, ...] = ()
    length_limited = False

    header = _dkim_header(raw_message)
    if header:
        tags = _tags(header)
        selector = tags.get("s")
        d_domain = tags.get("d")
        signed = tuple(h.strip().lower() for h in tags.get("h", "").split(":") if h.strip())
        length_limited = "l" in tags

    if not header:
        return DkimVerification(
            result=AuthResult.NONE,
            selector=None,
            d_domain=None,
            signed_headers=(),
            body_length_limited=False,
            caveat="The message carries no DKIM-Signature header.",
        )

    # Is the selector's public key still published? This has to be established
    # BEFORE interpreting a verification failure. dkimpy returns False both for
    # "the signature is invalid" and for "the key could not be fetched", and
    # those mean opposite things: the first accuses the sender, the second says
    # the evidence has expired. Key rotation is routine, so conflating them
    # would produce false accusations against legitimate senders.
    key_published = _selector_key_published(selector, d_domain)
    if not key_published:
        return DkimVerification(
            result=AuthResult.INDETERMINATE,
            selector=selector,
            d_domain=d_domain,
            signed_headers=signed,
            body_length_limited=length_limited,
            caveat=(
                f"The public key for selector '{selector}' is no longer published at "
                f"{selector}._domainkey.{d_domain}, so the signature cannot be "
                f"verified. Key rotation is routine: this is an expired check, NOT a "
                f"failed one, and must not be read as evidence against the sender."
            ),
        )

    try:
        import dkim

        verified = dkim.verify(raw_message)
        result = AuthResult.PASS if verified else AuthResult.FAIL
        caveat = None
        if not verified:
            caveat = (
                "Signature did not verify against the currently published key. The "
                "message was altered after signing, or the signature was never valid."
            )
    except Exception as exc:
        # A missing or rotated selector key is the common case and is NOT a
        # failure: it means the signature can no longer be checked.
        result = AuthResult.INDETERMINATE
        caveat = (
            f"Signature could not be verified ({type(exc).__name__}). The selector's "
            f"public key may no longer be published -- key rotation is routine, and "
            f"an unverifiable signature is not a failed one."
        )
        log.debug("dkim.indeterminate", error=str(exc)[:120])

    weaknesses: list[str] = []
    if signed and "from" not in signed:
        weaknesses.append("the From header is NOT covered by the signature")
    if length_limited:
        weaknesses.append("an l= body-length limit permits content to be appended")
    if weaknesses:
        caveat = "; ".join(filter(None, [caveat, "Signature weakness: " + ", ".join(weaknesses)]))

    return DkimVerification(
        result=result,
        selector=selector,
        d_domain=d_domain,
        signed_headers=signed,
        body_length_limited=length_limited,
        caveat=caveat,
    )


def fetch_dmarc(domain: str) -> DmarcPolicy:
    """Fetch the DMARC policy for a domain's organisational domain."""
    org = registrable_domain(domain)
    lookup = txt(f"_dmarc.{org}")
    record = next((r for r in lookup.records if r.lower().startswith("v=dmarc1")), None)

    if record is None:
        return DmarcPolicy(
            domain=org,
            found=False,
            policy=None,
            subdomain_policy=None,
            alignment_spf="r",
            alignment_dkim="r",
            raw=None,
            resolved=lookup.resolved,
        )

    tags = _tags(record, separator=";")
    return DmarcPolicy(
        domain=org,
        found=True,
        policy=tags.get("p"),
        subdomain_policy=tags.get("sp"),
        alignment_spf=tags.get("aspf", "r"),
        alignment_dkim=tags.get("adkim", "r"),
        raw=record,
        resolved=True,
    )


def fetch_spf(domain: str) -> SpfRecord:
    """Fetch the SPF record. Corroborating context only -- see the module docstring."""
    lookup = txt(domain)
    record = next((r for r in lookup.records if r.lower().startswith("v=spf1")), None)
    if record is None:
        return SpfRecord(
            domain=domain,
            found=False,
            raw=None,
            all_qualifier=None,
            permissive=False,
            resolved=lookup.resolved,
        )

    match = _SPF_ALL.search(record)
    qualifier = match.group("qualifier") if match else None
    return SpfRecord(
        domain=domain,
        found=True,
        raw=record,
        all_qualifier=qualifier,
        # "+all" authorises the entire internet to send as this domain. It is
        # almost always a misconfiguration and occasionally deliberate abuse.
        permissive=qualifier in ("+", None) if match else False,
        resolved=True,
    )


def aligned(identifier_domain: str | None, from_domain: str | None, mode: str = "r") -> bool | None:
    """DMARC alignment. ``mode`` is 's' for strict, 'r' for relaxed."""
    if not identifier_domain or not from_domain:
        return None
    if mode == "s":
        return identifier_domain.lower() == from_domain.lower()
    return registrable_domain(identifier_domain) == registrable_domain(from_domain)


def _selector_key_published(selector: str | None, domain: str | None) -> bool:
    """Whether the DKIM public key is still retrievable.

    Determines which of two very different conclusions a verification failure
    supports. See the call site.
    """
    if not selector or not domain:
        return False
    lookup = txt(f"{selector}._domainkey.{domain}")
    return lookup.resolved and any("p=" in record for record in lookup.records)


def _dkim_header(raw: bytes) -> str | None:
    try:
        import email
        import email.policy

        message = email.message_from_bytes(raw, policy=email.policy.default)
        value = message.get("DKIM-Signature")
        return str(value) if value else None
    except Exception:
        return None


def _tags(value: str, separator: str = ";") -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in value.split(separator):
        if "=" in part:
            key, _, val = part.partition("=")
            tags[key.strip().lower()] = val.strip()
    return tags
