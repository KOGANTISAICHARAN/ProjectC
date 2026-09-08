"""Trust-boundary origin reconstruction.

The product's centrepiece, and the reason it is not another header viewer.

The goal is NOT "geolocate the bottom Received header". It is to find the
**First Externally Observed Sender (FEOS)**: the IP address that the earliest
MTA we are prepared to vouch for actually recorded as its TCP peer. Everything
below that point is narrative the sender wrote; everything at or above it is
testimony from infrastructure with a reputation to lose.

What may and may not be claimed from this is fixed in docs/CLAIM_CONTRACT.md and
is generated here as ``claim_text`` -- once, from one place -- so the sentence
cannot drift into overclaiming inside a template.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import timedelta

from app.core.logging import get_logger
from app.models.enums import HopRole, IpClass, TrustState
from app.services.forensics.received import Hop

log = get_logger(__name__)

#: Autonomous systems whose MTAs we accept as witnesses, with the hostname
#: patterns their receiving hosts use. BOTH must match: an ASN alone is not
#: enough, because a tenant of a cloud provider is not that provider.
TRUSTED_PROVIDERS: dict[str, tuple[str, ...]] = {
    "microsoft": ("outlook.com", "protection.outlook.com", "office365.com", "microsoft.com"),
    "google": ("google.com", "googlemail.com", "gmail.com", "mx.google.com"),
    "proofpoint": ("pphosted.com", "proofpoint.com"),
    "mimecast": ("mimecast.com",),
    "barracuda": ("barracudanetworks.com", "ess.barracuda.com"),
    "amazon_ses": ("amazonses.com", "amazonaws.com"),
}

#: Shared email service providers. A message whose FEOS is one of these came
#: from *behind* that provider; the true origin is recoverable only by legal
#: process to them, so confidence is reduced and the limitation is stated.
SHARED_ESP_MARKERS = (
    "sendgrid.net",
    "mailgun.org",
    "mandrillapp.com",
    "amazonses.com",
    "sparkpostmail.com",
    "mailchimp.com",
    "constantcontact.com",
)

#: Clock skew tolerated before a non-monotonic timestamp is treated as forgery.
CLOCK_SKEW = timedelta(minutes=5)


@dataclass(slots=True)
class OriginResult:
    feos_ip: str | None
    boundary_seq: int | None
    confidence: int
    breakdown: dict[str, int]
    flags: list[str]
    claim_text: str
    hop_roles: dict[int, HopRole] = field(default_factory=dict)
    hop_trust: dict[int, TrustState] = field(default_factory=dict)
    hop_anomalies: dict[int, list[str]] = field(default_factory=dict)


def _classify_hop(hop: Hop, org_domains: tuple[str, ...]) -> HopRole:
    host = (hop.by_host or "").lower()
    rdns = (hop.rdns_claim or "").lower()

    if any(host.endswith(d) for d in org_domains):
        return HopRole.ORG_INTERNAL
    for patterns in TRUSTED_PROVIDERS.values():
        # Receiving hostname must match a known provider pattern. Checked on
        # `by_host` -- what the receiver says about itself -- not on the HELO the
        # client supplied.
        if any(host.endswith(p) or host == p for p in patterns):
            return HopRole.TRUSTED_PROVIDER
    if rdns and any(rdns.endswith(p) for ps in TRUSTED_PROVIDERS.values() for p in ps):
        return HopRole.TRUSTED_PROVIDER
    return HopRole.EXTERNAL


def _integrity_flags(
    hops: list[Hop], boundary: int | None
) -> tuple[list[str], dict[int, list[str]]]:
    """Internal-consistency checks on the chain itself.

    An attacker writing fake Received headers has to invent times and hostnames
    that agree with the real hops above them. They usually do not.
    """
    flags: list[str] = []
    per_hop: dict[int, list[str]] = {}

    def note(seq: int, code: str) -> None:
        per_hop.setdefault(seq, []).append(code)
        if code not in flags:
            flags.append(code)

    # Chronology: walking from oldest to newest, timestamps must not go backwards.
    ordered = [h for h in reversed(hops) if h.timestamp is not None]
    for earlier, later in itertools.pairwise(ordered):
        if (
            later.timestamp is not None
            and earlier.timestamp is not None
            and later.timestamp + CLOCK_SKEW < earlier.timestamp
        ):
            note(later.seq, "timestamp_not_monotonic")

    # Handoff continuity: hop[i] should have been received from the host that
    # hop[i+1] says it is. A clean break is an injected header.
    for i in range(len(hops) - 1):
        upper, lower = hops[i], hops[i + 1]
        claimed = (upper.helo or "").lower()
        actual = (lower.by_host or "").lower()
        if (
            claimed
            and actual
            and claimed != actual
            and not (claimed.endswith(actual) or actual.endswith(claimed))
        ):
            note(lower.seq, "handoff_discontinuity")

    # A private address appearing after a public one is not a route a message
    # can take -- but ONLY below the trust boundary. Above it, private hops are
    # the normal internal handoff from a mail provider to the organisation's own
    # gateway, and flagging those would fire on virtually every legitimate
    # enterprise email.
    if boundary is not None:
        below = [h for h in hops if h.seq > boundary]
        seen_public = False
        for hop in reversed(below):
            if hop.ip_class is IpClass.PUBLIC:
                seen_public = True
            elif seen_public and hop.ip_class in (IpClass.PRIVATE, IpClass.LOOPBACK):
                note(hop.seq, "private_ip_after_public")

    return flags, per_hop


def reconstruct_origin(
    hops: list[Hop],
    *,
    org_domains: tuple[str, ...] = (),
    extra_auth_flags: tuple[str, ...] = (),
) -> OriginResult:
    """Locate the trust boundary and the first externally observed sender."""
    if not hops:
        return OriginResult(
            feos_ip=None,
            boundary_seq=None,
            confidence=10,
            breakdown={"no_received_headers": -40},
            flags=["no_received_headers"],
            claim_text=(
                "No Received headers are present, so no sending infrastructure can be "
                "identified. This is not evidence of legitimacy or of forgery."
            ),
        )

    roles = {h.seq: _classify_hop(h, org_domains) for h in hops}

    # Descend from our own infrastructure until trust runs out.
    # Collected here because the boundary walk can itself raise a flag, and the
    # integrity checks below need the boundary to run.
    pre_flags: list[str] = []
    boundary: int | None = None
    for hop in hops:
        if roles[hop.seq] in (HopRole.ORG_INTERNAL, HopRole.TRUSTED_PROVIDER):
            boundary = hop.seq
            continue
        if roles[hop.seq] is HopRole.KNOWN_FORWARDER:
            boundary = hop.seq
            if "forwarding_suspected" not in pre_flags:
                pre_flags.append("forwarding_suspected")
            continue
        break  # first EXTERNAL hop: we have crossed over

    # Integrity checks need the boundary: some anomalies are only anomalous
    # below it.
    flags, per_hop = _integrity_flags(hops, boundary)
    flags = pre_flags + flags
    flags.extend(extra_auth_flags)

    trust: dict[int, TrustState] = {}
    for hop in hops:
        if boundary is not None and hop.seq < boundary:
            trust[hop.seq] = TrustState.VOUCHED
        elif boundary is not None and hop.seq == boundary:
            trust[hop.seq] = TrustState.BOUNDARY
        elif "timestamp_not_monotonic" in per_hop.get(hop.seq, []):
            trust[hop.seq] = TrustState.FORGED
        else:
            trust[hop.seq] = TrustState.ASSERTED

    feos_ip: str | None = None
    if boundary is not None:
        # The FEOS is the peer that the boundary hop observed -- never a HELO
        # string, never a header the sender wrote.
        candidate = hops[boundary]
        if candidate.ip_class is IpClass.PUBLIC and candidate.observed_ip:
            feos_ip = candidate.observed_ip
        else:
            # The boundary hop saw a NAT or internal address; step down to the
            # first public address the sender's own chain admits to.
            for hop in hops[boundary + 1 :]:
                if hop.ip_class is IpClass.PUBLIC and hop.observed_ip:
                    feos_ip = hop.observed_ip
                    break

    confidence, breakdown = _score_confidence(hops, boundary, feos_ip, flags, roles)

    return OriginResult(
        feos_ip=feos_ip,
        boundary_seq=boundary,
        confidence=confidence,
        breakdown=breakdown,
        flags=flags,
        claim_text=_claim_text(feos_ip, boundary, hops, roles, confidence, flags),
        hop_roles=roles,
        hop_trust=trust,
        hop_anomalies=per_hop,
    )


def _score_confidence(
    hops: list[Hop],
    boundary: int | None,
    feos_ip: str | None,
    flags: list[str],
    roles: dict[int, HopRole],
) -> tuple[int, dict[str, int]]:
    """Additive, published, and shown in the UI.

    Every term is named so a reviewer can re-derive the number. A confidence
    figure nobody can reproduce is the first thing an opposing expert attacks.
    """
    breakdown: dict[str, int] = {"base": 50}

    if boundary is None:
        breakdown["no_trusted_receiving_infrastructure"] = -35
    elif roles[boundary] in (HopRole.ORG_INTERNAL, HopRole.TRUSTED_PROVIDER):
        breakdown["boundary_at_recognised_infrastructure"] = 20

    if "handoff_discontinuity" not in flags:
        breakdown["handoff_continuity_intact"] = 10
    else:
        breakdown["handoff_discontinuity"] = -10

    if "timestamp_not_monotonic" not in flags:
        breakdown["timestamps_monotonic"] = 10
    else:
        breakdown["forged_header_below_boundary"] = -10

    if feos_ip is None:
        breakdown["no_public_sender_observed"] = -20

    if "forwarding_suspected" in flags:
        breakdown["forwarding_suspected"] = -15
    if "forged_authentication_results" in flags:
        # Evidence of deliberate evasion. It lowers confidence in the chain while
        # raising suspicion of the message -- two different judgements.
        breakdown["injected_authentication_results"] = -5
    if len(hops) < 2:
        breakdown["single_hop_nothing_to_corroborate"] = -8

    for hop in hops:
        if hop.rdns_claim and any(m in hop.rdns_claim for m in SHARED_ESP_MARKERS):
            breakdown["shared_esp_true_origin_unrecoverable"] = -12
            break

    # Clamped to 95. Never 100: certainty is not available from header evidence.
    total = max(5, min(95, sum(breakdown.values())))
    return total, breakdown


def _claim_text(
    feos_ip: str | None,
    boundary: int | None,
    hops: list[Hop],
    roles: dict[int, HopRole],
    confidence: int,
    flags: list[str],
) -> str:
    """The sentence the UI and the PDF both render.

    Generated once, here, from the claim contract -- so it cannot drift into
    "the attacker is in X" inside a template somebody edits later.
    """
    if feos_ip is None or boundary is None:
        return (
            "No trustworthy receiving infrastructure was identified in the Received "
            "chain, so no sending infrastructure can be attributed. Refusing to "
            "answer is deliberate: a confident answer from insufficient data is the "
            "failure mode this system is built to avoid."
        )

    boundary_host = hops[boundary].by_host or "the first trusted hop"
    trusted = roles[boundary] in (HopRole.ORG_INTERNAL, HopRole.TRUSTED_PROVIDER)
    infra = f"before the message entered {boundary_host}" if trusted else "in the observed chain"

    text = (
        f"Probable originating infrastructure: {feos_ip} "
        f"(confidence {confidence}%). This is the earliest externally observed "
        f"sending infrastructure {infra}. "
        f"It does NOT establish the physical location of the operator: the host may "
        f"be rented, compromised, a proxy, or a legitimate mailbox whose owner is "
        f"also a victim."
    )
    if "forwarding_suspected" in flags:
        text += " Forwarding was detected, which legitimately breaks authentication."
    return text
