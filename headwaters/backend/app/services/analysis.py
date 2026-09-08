"""Band A: the synchronous, offline-safe analysis pipeline.

Runs with **zero outbound network calls** and returns a defensible verdict in
well under a second. Everything that can fail -- DNS, RDAP, threat intel, the
model -- belongs to Band B and only ever *upgrades* a case that is already
complete.

That property is worth more than any single feature: unplug the network and the
product still works, degraded and honest about it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.models.enums import FindingGroup, Severity
from app.services.forensics import auth as auth_mod
from app.services.forensics import lookalike, parser, received
from app.services.forensics.origin import OriginResult, reconstruct_origin
from app.services.scoring.fusion import FusionResult, RawFinding, fuse

log = get_logger(__name__)

#: Domains and identities the organisation considers its own. Configuration in
#: production (`orgs.settings`); these defaults drive the bundled demo corpus.
DEFAULT_PROTECTED_DOMAINS = ("kaverifs.com",)
DEFAULT_PROTECTED_IDENTITIES = ("Anand Rao", "Chief Executive Officer", "CEO", "CFO")
DEFAULT_TRUSTED_AUTHSERV = ("kaverifs.com", "outlook.com", "protection.outlook.com", "google.com")

#: Free-mail providers. An executive "sending" from one is a strong signal, and
#: a Reply-To pointing at one is stronger still.
FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com"}

_URGENCY = (
    "immediately",
    "urgent",
    "asap",
    "right away",
    "before close",
    "today",
    "time-critical",
    "time critical",
    "deadline",
    "expires",
)
_SECRECY = (
    "do not discuss",
    "confidential",
    "keep this between",
    "don't tell",
    "do not tell",
    "without informing",
    "discreet",
)
_FINANCIAL = (
    "wire",
    "transfer",
    "payment",
    "invoice",
    "beneficiary",
    "bank details",
    "remittance",
    "escrow",
    "account number",
)
_CREDENTIAL = (
    "verify your account",
    "sign in",
    "log in",
    "login",
    "password",
    "portal",
    "re-authenticate",
    "confirm your identity",
)
_AUTHORITY = (
    "i am in",
    "board meeting",
    "do not call",
    "don't call",
    "as ceo",
    "on my authority",
    "i need you to",
)


#: One plain sentence per rule, for readers who are not security specialists.
#:
#: Applied centrally rather than at each construction site, because several rule
#: ids are built at run time (``f"AUTH_{mech}_FAIL"``, the content loop, the
#: identity signals) and a literal string beside each one would silently miss
#: them. Active voice; says what the reader should CONCLUDE, not what the
#: protocol did.
PLAIN_BY_RULE: dict[str, str] = {
    "AUTH_INJECTED_RESULTS": (
        "The sender forged a security-check result inside the email, hoping an "
        "automated tool would read it and wave the message through."
    ),
    "AUTH_NO_TRUSTED_RESULTS": (
        "No mail server we recognise vouched for this message, so we cannot confirm "
        "who sent it. That is missing information, not proof of anything."
    ),
    "AUTH_SPF_PASS_UNALIGNED": (
        "The sender proved they own THEIR domain — not the one they appear to be "
        "writing from. These checks ask whether a domain's paperwork matches "
        "itself, never whether the sender is who they claim to be."
    ),
    "AUTH_DKIM_PASS_UNALIGNED": (
        "The signature on this email belongs to a different domain than the one "
        "shown in the From line."
    ),
    "AUTH_DMARC_PASS_UNALIGNED": (
        "The security checks passed for a domain the sender controls, which is not "
        "the domain they appear to be writing from."
    ),
    "AUTH_SPF_FAIL": (
        "The server that sent this email is not authorised to send for the domain it claims."
    ),
    "AUTH_DKIM_FAIL": (
        "The email's signature does not match, so the message was altered after "
        "signing or was never properly signed."
    ),
    "AUTH_DMARC_FAIL": ("This email failed the domain owner's own anti-impersonation policy."),
    "AUTH_ARC_FAIL": "The forwarding chain on this email could not be verified.",
    "AUTH_DMARC_ALIGNED_ESTABLISHED": (
        "The sender's identity checks out for the domain shown. This lowers the "
        "score unless someone is also impersonating a known person."
    ),
    "IDENT_DUPLICATE_FROM": (
        "The email has two different 'From' lines. Your mail app shows one and a "
        "filter may read the other — a deliberate trick."
    ),
    "IDENT_INVISIBLE_CHARS": (
        "The sender's name contains hidden characters that make it display as "
        "something other than what it is. There is no honest reason to do this."
    ),
    "IDENT_PROTECTED_DISPLAY_NAME": (
        "The sender's display name matches a senior person at your organisation. "
        "Most mail apps show only this name, not the address behind it."
    ),
    "IDENT_LOOKALIKE_DOMAIN": (
        "The sender's domain is a near-copy of one of yours — close enough to "
        "misread at a glance. The attacker owns it, so it passes every check."
    ),
    "IDENT_REPLY_TO_DIVERGENT": (
        "If you hit Reply, your answer goes somewhere other than where this email "
        "appears to come from."
    ),
    "IDENT_REPLY_TO_FREEMAIL": (
        "Replies to this business email would go to a personal webmail account — a "
        "core sign of payment fraud."
    ),
    "IDENT_RETURN_PATH_DIVERGENT": (
        "The address that would receive bounces differs from the visible sender."
    ),
    "INFRA_FORGED_RECEIVED": (
        "The delivery stamps on this email contradict each other — the times run "
        "backwards. Someone wrote them by hand."
    ),
    "INFRA_HANDOFF_BREAK": (
        "The delivery trail has a gap: one server does not match the one before it."
    ),
    "INFRA_NO_TRUST_BOUNDARY": (
        "We could not recognise any mail server in the delivery trail, so we will "
        "not guess where this came from."
    ),
    "INFRA_ASSERTED_HOPS": (
        "Part of the delivery trail was written by the sender themselves. We keep "
        "it on record but do not treat it as evidence."
    ),
    "URL_CREDENTIAL_LANDING": (
        "A link in this email leads to a page asking for a password or sign-in."
    ),
    "URL_LOOKALIKE_HOST": ("A link points at a web address built to look like one of yours."),
    "ATTACH_TYPE_MISMATCH": (
        "An attachment's file extension does not match what the file actually is."
    ),
    "ATTACH_ARCHIVE": (
        "The email carries a zip or archive. We record its fingerprint but never open it."
    ),
    "ATTACH_PRESENT": (
        "The email has an attachment. We recorded its fingerprint without opening it."
    ),
    "CONTENT_URGENCY": (
        "The message pushes for immediate action, which is how fraud gets past someone's judgement."
    ),
    "CONTENT_AUTHORITY": ("The message leans on seniority and discourages you from checking."),
    "CONTENT_SECRECY": (
        "The message asks you to keep it quiet — a strong sign of fraud, because "
        "secrecy exists to stop you verifying."
    ),
    "CONTENT_FINANCIAL": ("The message asks for money to move, or for bank details to change."),
    "CONTENT_CREDENTIAL": ("The message asks you to sign in or confirm a password."),
}


def _attach_plain(findings: list[RawFinding]) -> None:
    """Fill in the plain sentence for any finding that lacks one."""
    for finding in findings:
        if not finding.plain:
            finding.plain = PLAIN_BY_RULE.get(finding.rule_id)


@dataclass(slots=True)
class AnalysisResult:
    parsed: parser.ParsedEmail
    hops: list[received.Hop]
    origin: OriginResult
    auth: auth_mod.AuthEvaluation
    findings: list[RawFinding]
    fusion: FusionResult
    from_display: str | None = None
    from_address: str | None = None
    from_domain: str | None = None
    reply_to_address: str | None = None
    return_path: str | None = None
    message_id: str | None = None
    groups_with_data: set[FindingGroup] = field(default_factory=set)


def analyse(
    raw: bytes,
    *,
    protected_domains: tuple[str, ...] = DEFAULT_PROTECTED_DOMAINS,
    protected_identities: tuple[str, ...] = DEFAULT_PROTECTED_IDENTITIES,
    trusted_authserv: tuple[str, ...] = DEFAULT_TRUSTED_AUTHSERV,
) -> AnalysisResult:
    parsed = parser.parse_email(raw)

    from_pairs = parser.addresses_in(parsed.get("From"))
    from_display, from_address = from_pairs[0] if from_pairs else (None, None)
    from_domain = from_address.rsplit("@", 1)[-1] if from_address and "@" in from_address else None

    reply_pairs = parser.addresses_in(parsed.get("Reply-To"))
    reply_to_address = reply_pairs[0][1] if reply_pairs else None
    reply_to_domain = (
        reply_to_address.rsplit("@", 1)[-1]
        if reply_to_address and "@" in reply_to_address
        else None
    )

    return_path_pairs = parser.addresses_in(parsed.get("Return-Path"))
    return_path = return_path_pairs[0][1] if return_path_pairs else None
    message_id = parsed.get("Message-ID")

    hops = received.parse_received_chain(parsed.get_all("Received"))
    ar_headers = parsed.get_all("Authentication-Results")

    auth_eval = auth_mod.evaluate_authentication(
        ar_headers, trusted_authserv_suffixes=trusted_authserv, from_domain=from_domain
    )

    extra_flags: tuple[str, ...] = (
        ("forged_authentication_results",) if auth_eval.forged_pass_detected else ()
    )
    origin = reconstruct_origin(hops, org_domains=protected_domains, extra_auth_flags=extra_flags)

    findings: list[RawFinding] = []

    #: The groups Band A actually evaluates. Declared explicitly rather than
    #: inferred from the findings produced: a group that ran and found nothing is
    #: evidence of absence, while a group that never ran is absence of evidence,
    #: and the score must not treat them alike.
    groups: set[FindingGroup] = {
        FindingGroup.AUTHENTICATION,
        FindingGroup.IDENTITY,
        FindingGroup.INFRASTRUCTURE,
        FindingGroup.URL_DOMAIN,
        FindingGroup.CONTENT,
        FindingGroup.ATTACHMENT,
    }
    # THREAT_INTEL and CAMPAIGN belong to Band B and are deliberately absent
    # here; data_completeness reports 6/8 so the UI can say so.

    # DMARC passes if EITHER SPF or DKIM aligns with the From domain. Every
    # sender using an email service provider -- Amazon SES, SendGrid, Mailchimp
    # -- has SPF aligned to the provider's bounce domain and DKIM aligned to
    # their own. That is the standard, correct configuration, so several rules
    # below must not treat it as suspicious.
    dmarc_aligned = _dmarc_aligned(auth_eval)

    findings += _authentication_findings(
        auth_eval, parsed, from_domain, dmarc_aligned=dmarc_aligned
    )
    findings += _identity_findings(
        parsed,
        from_display,
        from_domain,
        reply_to_domain,
        return_path,
        protected_domains,
        protected_identities,
        dmarc_aligned=dmarc_aligned,
    )
    findings += _infrastructure_findings(origin, hops)
    findings += _url_findings(parsed, from_domain, protected_domains, dmarc_aligned=dmarc_aligned)
    findings += _attachment_findings(parsed)
    findings += _content_findings(parsed)

    _attach_plain(findings)

    fusion = fuse(findings, groups_evaluated=groups)

    log.info(
        "analysis.complete",
        score=fusion.score,
        band=fusion.band.value,
        classification=fusion.classification.value,
        findings=len(findings),
        hops=len(hops),
        feos=origin.feos_ip,
        origin_confidence=origin.confidence,
    )

    return AnalysisResult(
        parsed=parsed,
        hops=hops,
        origin=origin,
        auth=auth_eval,
        findings=findings,
        fusion=fusion,
        from_display=from_display,
        from_address=from_address,
        from_domain=from_domain,
        reply_to_address=reply_to_address,
        return_path=return_path,
        message_id=message_id,
        groups_with_data=groups,
    )


# --------------------------------------------------------------------------
def _dmarc_aligned(auth_eval: auth_mod.AuthEvaluation) -> bool:
    """Did any identifier actually align with the From domain?

    This is the question that matters, and it is NOT the same as "did every
    mechanism align". Misalignment of one identifier is only evidence when
    nothing aligned at all.
    """
    return any(
        f.mechanism.value in ("dmarc", "dkim")
        and f.result_reported.value == "pass"
        and f.aligned is True
        for f in auth_eval.findings
    )


def _same_registrable(host: str, domain: str) -> bool:
    """Compare organisational domains, so ``mail.example.com`` matches
    ``example.com``."""
    from app.services.intel.dns import registrable_domain

    return registrable_domain(host) == registrable_domain(domain)


def _authentication_findings(
    auth_eval: auth_mod.AuthEvaluation,
    parsed: parser.ParsedEmail,
    from_domain: str | None,
    *,
    dmarc_aligned: bool = False,
) -> list[RawFinding]:
    out: list[RawFinding] = []

    if auth_eval.forged_pass_detected:
        out.append(
            RawFinding(
                group=FindingGroup.AUTHENTICATION,
                rule_id="AUTH_INJECTED_RESULTS",
                plain=(
                    "The sender forged a security-check result inside the email, hoping an "
                    "automated tool would read it and wave the message through."
                ),
                severity=Severity.CRITICAL,
                title="Forged Authentication-Results header injected by the sender",
                detail=(
                    "An Authentication-Results header asserting a pass was present from an "
                    "authserv-id we do not recognise. Only the topmost header from trusted "
                    "infrastructure is evaluated; this one was discarded. Injecting it is a "
                    "deliberate attempt to defeat automated analysis, and is scored as such."
                ),
                evidence_ref="Authentication-Results",
                mitre_technique="T1656",
            )
        )

    if not auth_eval.findings:
        out.append(
            RawFinding(
                group=FindingGroup.AUTHENTICATION,
                rule_id="AUTH_NO_TRUSTED_RESULTS",
                plain=(
                    "No mail server we recognise vouched for this message, so we cannot "
                    "confirm who sent it. That is missing information, not proof of anything."
                ),
                severity=Severity.MEDIUM,
                title="No Authentication-Results from recognised infrastructure",
                detail=(
                    "Authentication cannot be established from the message alone. This is "
                    "not evidence of forgery -- it is an absence of evidence, and the score "
                    "reflects reduced data completeness rather than guilt."
                ),
                evidence_ref="Authentication-Results",
            )
        )
        return out

    for finding in auth_eval.findings:
        mech = finding.mechanism.value.upper()
        passed = finding.result_reported.value == "pass"

        if passed and finding.aligned is False and not dmarc_aligned:
            out.append(
                RawFinding(
                    group=FindingGroup.AUTHENTICATION,
                    rule_id=f"AUTH_{mech}_PASS_UNALIGNED",
                    severity=Severity.HIGH,
                    title=f"{mech} passed, but not for the identity shown to the recipient",
                    detail=(
                        f"{mech} passed for a domain the sender controls, which is exactly "
                        f"what an attacker gets by registering their own lookalike domain "
                        f"and configuring it correctly. It does not align with the From "
                        f"domain a human reads ({from_domain}). Authentication asks whether "
                        f"a domain's paperwork matches itself, never whether the sender is "
                        f"who they claim to be."
                    ),
                    evidence_ref=f"Authentication-Results ({finding.authserv_id})",
                )
            )
        elif not passed and finding.result_reported.value in ("fail", "softfail"):
            out.append(
                RawFinding(
                    group=FindingGroup.AUTHENTICATION,
                    rule_id=f"AUTH_{mech}_FAIL",
                    severity=Severity.HIGH,
                    title=f"{mech} failed",
                    detail=f"Reported {mech.lower()}={finding.result_reported.value} by "
                    f"{finding.authserv_id}. {finding.caveat or ''}".strip(),
                    evidence_ref=f"Authentication-Results ({finding.authserv_id})",
                )
            )
        elif passed and finding.aligned is True and finding.mechanism.value == "dmarc":
            out.append(
                RawFinding(
                    group=FindingGroup.AUTHENTICATION,
                    rule_id="AUTH_DMARC_ALIGNED_ESTABLISHED",
                    plain=(
                        "The sender's identity checks out for the domain shown. This lowers the "
                        "score unless someone is also impersonating a known person."
                    ),
                    severity=Severity.INFO,
                    title="DMARC passed and is aligned to the sending identity",
                    detail="Triggers the legitimacy dampener unless impersonation of a "
                    "protected identity is also present.",
                    evidence_ref="Authentication-Results",
                )
            )
    return out


def _identity_findings(
    parsed: parser.ParsedEmail,
    from_display: str | None,
    from_domain: str | None,
    reply_to_domain: str | None,
    return_path: str | None,
    protected_domains: tuple[str, ...],
    protected_identities: tuple[str, ...],
    *,
    dmarc_aligned: bool = False,
) -> list[RawFinding]:
    out: list[RawFinding] = []

    if len(parsed.get_all("From")) > 1:
        out.append(
            RawFinding(
                group=FindingGroup.IDENTITY,
                rule_id="IDENT_DUPLICATE_FROM",
                plain=(
                    "The email has two different 'From' lines. Your mail app shows one and a "
                    "filter may read the other -- a deliberate trick."
                ),
                severity=Severity.CRITICAL,
                title="Multiple From headers",
                detail=(
                    "RFC 5322 permits exactly one From header. Two is both a violation and "
                    "a known attack: some mail clients render the first and some filters "
                    "evaluate the last, so the human and the machine can be shown "
                    "different senders."
                ),
                evidence_ref="From",
                mitre_technique="T1656",
            )
        )

    for signal in lookalike.analyse_identity(
        from_display=from_display,
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        protected_domains=protected_domains,
        protected_identities=protected_identities,
    ):
        out.append(
            RawFinding(
                group=FindingGroup.IDENTITY,
                rule_id=signal.rule_id,
                severity=Severity(signal.severity),
                title=signal.title,
                detail=signal.detail,
                evidence_ref=signal.evidence,
                mitre_technique="T1656" if "IDENT_" in signal.rule_id else None,
            )
        )

    if reply_to_domain and reply_to_domain in FREEMAIL and from_domain not in FREEMAIL:
        out.append(
            RawFinding(
                group=FindingGroup.IDENTITY,
                rule_id="IDENT_REPLY_TO_FREEMAIL",
                plain=(
                    "Replies to this business email would go to a personal webmail account -- "
                    "a core sign of payment fraud."
                ),
                severity=Severity.HIGH,
                title="Replies are directed to a free webmail account",
                detail="A corporate sender whose replies leave for a consumer mailbox is a "
                "core business-email-compromise pattern.",
                evidence_ref=f"Reply-To: {reply_to_domain}",
            )
        )

    # Suppressed when an identifier aligned: a divergent Return-Path is then
    # just the email service provider's bounce domain, which is what every
    # ESP-sent message looks like.
    if return_path and from_domain and not dmarc_aligned:
        rp_domain = return_path.rsplit("@", 1)[-1]
        # Compared at the ORGANISATIONAL domain: `mail.example.com` bouncing for
        # `example.com` is a subdomain, not a divergence, and treating it as one
        # fires on a large share of correctly configured senders.
        if not _same_registrable(rp_domain, from_domain):
            out.append(
                RawFinding(
                    group=FindingGroup.IDENTITY,
                    rule_id="IDENT_RETURN_PATH_DIVERGENT",
                    plain=(
                        "The address that would receive bounces differs from the visible sender."
                    ),
                    severity=Severity.MEDIUM,
                    title="Envelope sender differs from the visible From domain",
                    detail=(
                        f"Return-Path is '{rp_domain}' while From is '{from_domain}'. "
                        f"Return-Path is written by the receiving MTA from the SMTP "
                        f"envelope, so it is more trustworthy than From -- and divergence "
                        f"is the structural precondition for SPF misalignment."
                    ),
                    evidence_ref=f"Return-Path: {return_path}",
                )
            )
    return out


def _infrastructure_findings(origin: OriginResult, hops: list[received.Hop]) -> list[RawFinding]:
    out: list[RawFinding] = []

    if "timestamp_not_monotonic" in origin.flags:
        out.append(
            RawFinding(
                group=FindingGroup.INFRASTRUCTURE,
                rule_id="INFRA_FORGED_RECEIVED",
                plain=(
                    "The delivery stamps on this email contradict each other -- the times run "
                    "backwards. Someone wrote them by hand."
                ),
                severity=Severity.HIGH,
                title="Forged Received header: timestamps run backwards",
                detail=(
                    "A hop claims a time earlier than a hop that came after it, beyond any "
                    "plausible clock skew. Headers below the trust boundary are written by "
                    "the sender; this one contradicts the hops above it."
                ),
                evidence_ref="Received chain",
                mitre_technique="T1656",
            )
        )

    if "handoff_discontinuity" in origin.flags:
        out.append(
            RawFinding(
                group=FindingGroup.INFRASTRUCTURE,
                rule_id="INFRA_HANDOFF_BREAK",
                plain=(
                    "The delivery trail has a gap: one server does not match the one before it."
                ),
                severity=Severity.MEDIUM,
                title="Break in Received-chain continuity",
                detail="A hop was received from a host that the hop below it does not claim "
                "to be. Consistent with an injected header, though some legitimate "
                "relays rewrite hostnames.",
                evidence_ref="Received chain",
            )
        )

    if origin.boundary_seq is None and hops:
        out.append(
            RawFinding(
                group=FindingGroup.INFRASTRUCTURE,
                rule_id="INFRA_NO_TRUST_BOUNDARY",
                plain=(
                    "We could not recognise any of the mail servers in the delivery trail, so "
                    "we will not guess where this came from."
                ),
                severity=Severity.MEDIUM,
                title="No recognised receiving infrastructure in the Received chain",
                detail="Origin cannot be attributed. Refusing to answer is deliberate: a "
                "confident answer from insufficient data is the failure mode this "
                "system exists to avoid.",
                evidence_ref="Received chain",
            )
        )

    if origin.feos_ip and origin.boundary_seq is not None:
        asserted = sum(1 for h in hops if h.seq > origin.boundary_seq)
        if asserted:
            out.append(
                RawFinding(
                    group=FindingGroup.INFRASTRUCTURE,
                    rule_id="INFRA_ASSERTED_HOPS",
                    plain=(
                        "Part of the delivery trail was written by the sender themselves. We keep "
                        "it on record but do not treat it as evidence."
                    ),
                    severity=Severity.LOW,
                    title=f"{asserted} Received header(s) below the trust boundary",
                    detail="Retained and displayed as the sender's own claimed path, but "
                    "never scored and never geolocated with confidence.",
                    evidence_ref=f"hops {origin.boundary_seq + 1}..{len(hops) - 1}",
                )
            )
    return out


def _url_findings(
    parsed: parser.ParsedEmail,
    from_domain: str | None,
    protected_domains: tuple[str, ...],
    *,
    dmarc_aligned: bool = False,
) -> list[RawFinding]:
    out: list[RawFinding] = []
    if not parsed.urls:
        return out

    credential_markers = (
        "login",
        "signin",
        "sign-in",
        "verify",
        "auth",
        "portal",
        "account",
        "password",
        "sso",
    )
    for url in parsed.urls[:50]:
        lowered = url.lower()
        host = lowered.split("//", 1)[-1].split("/", 1)[0].split(":")[0]

        if any(m in lowered for m in credential_markers):
            # A sign-in link is only a signal when it LEAVES the authenticated
            # sender's own domain. A password-reset email from a DMARC-aligned
            # sender, linking back to that same sender, is the most common
            # legitimate transactional email there is -- flagging it makes the
            # system cry wolf on exactly the mail people receive most.
            same_domain = bool(from_domain and _same_registrable(host, from_domain))
            out.append(
                RawFinding(
                    group=FindingGroup.URL_DOMAIN,
                    rule_id="URL_CREDENTIAL_LANDING",
                    plain=(
                        "A link in this email leads to a page asking for a password or sign-in."
                    ),
                    severity=(
                        # Alignment proves the sender controls the domain. It does
                        # NOT prove the domain is trustworthy: an attacker who
                        # registers their own and configures it correctly aligns
                        # too. So this downgrades the signal rather than removing
                        # it -- a legitimate password reset lands in the benign
                        # band on its own, without the rule going blind.
                        Severity.LOW
                        if same_domain and dmarc_aligned
                        else Severity.MEDIUM
                        if same_domain
                        else Severity.HIGH
                    ),
                    title="Link points at a credential-entry page",
                    detail=(
                        "Sign-in or verification form on the sender's own "
                        "DMARC-aligned domain -- the shape of a legitimate password "
                        "reset. Recorded, but weighted low."
                        if same_domain and dmarc_aligned
                        else "Sign-in or verification form on the sender's own domain, "
                        "but no identifier aligned, so that domain is not established."
                        if same_domain
                        else "Sign-in or verification form on a domain other than the "
                        "sender's. Combined with an impersonated sender this is "
                        "credential harvesting."
                    ),
                    evidence_ref=url[:300],
                    mitre_technique="T1566.002",
                )
            )
            break

    for url in parsed.urls[:50]:
        host = url.lower().split("//", 1)[-1].split("/", 1)[0].split(":")[0]
        for protected in protected_domains:
            if host != protected and protected.split(".")[0] in host:
                out.append(
                    RawFinding(
                        group=FindingGroup.URL_DOMAIN,
                        rule_id="URL_LOOKALIKE_HOST",
                        plain=("A link points at a web address built to look like one of yours."),
                        severity=Severity.HIGH,
                        title=f"Link host imitates a protected domain ({protected})",
                        detail=f"'{host}' embeds the protected brand token but is not "
                        f"'{protected}'.",
                        evidence_ref=url[:300],
                        mitre_technique="T1566.002",
                    )
                )
                return out
    return out


def _attachment_findings(parsed: parser.ParsedEmail) -> list[RawFinding]:
    out: list[RawFinding] = []
    for attachment in parsed.attachments:
        if attachment.extension_mismatch:
            out.append(
                RawFinding(
                    group=FindingGroup.ATTACHMENT,
                    rule_id="ATTACH_TYPE_MISMATCH",
                    plain=(
                        "An attachment's file extension does not match what the file actually is."
                    ),
                    severity=Severity.HIGH,
                    title=f"Attachment extension disagrees with its declared type: "
                    f"{attachment.filename}",
                    detail=f"Declared as {attachment.content_type}.",
                    evidence_ref=attachment.sha256,
                    mitre_technique="T1566.001",
                )
            )
        elif attachment.is_archive:
            out.append(
                RawFinding(
                    group=FindingGroup.ATTACHMENT,
                    rule_id="ATTACH_ARCHIVE",
                    plain=(
                        "The email carries a zip or archive. We record its fingerprint but never "
                        "open it."
                    ),
                    severity=Severity.LOW,
                    title=f"Archive attachment: {attachment.filename}",
                    detail="Hashed and recorded. Deliberately NOT expanded: unpacking "
                    "attacker-supplied archives in-process is how a decompression "
                    "bomb takes a service down.",
                    evidence_ref=attachment.sha256,
                )
            )
        else:
            out.append(
                RawFinding(
                    group=FindingGroup.ATTACHMENT,
                    rule_id="ATTACH_PRESENT",
                    plain=(
                        "The email has an attachment. We recorded its fingerprint without opening "
                        "it."
                    ),
                    severity=Severity.LOW,
                    title=f"Attachment: {attachment.filename or attachment.content_type}",
                    detail=f"SHA-256 {attachment.sha256}. Never opened or executed; no "
                    f"threat-intelligence lookup performed (Band B, deferred).",
                    evidence_ref=attachment.sha256,
                )
            )
    return out


def _content_findings(parsed: parser.ParsedEmail) -> list[RawFinding]:
    """Deterministic keyword signals, NOT the AI layer.

    These are cheap lexical markers with a quoted evidence span. The semantic
    intent layer (Phase 7) replaces them with a schema-locked model call, still
    capped at the same 12 points -- because tone is a modifier of risk, never a
    source of it.
    """
    body = parsed.text_body
    lowered = body.lower()
    out: list[RawFinding] = []

    def quote_for(term: str) -> str:
        index = lowered.find(term)
        if index < 0:
            return term
        start, end = max(0, index - 60), min(len(body), index + len(term) + 60)
        return body[start:end].replace("\n", " ").strip()

    checks = (
        (_URGENCY, "CONTENT_URGENCY", "Urgency pressure", Severity.MEDIUM),
        (_AUTHORITY, "CONTENT_AUTHORITY", "Authority pressure", Severity.MEDIUM),
        (_SECRECY, "CONTENT_SECRECY", "Request for secrecy", Severity.HIGH),
        (_FINANCIAL, "CONTENT_FINANCIAL", "Financial instruction", Severity.MEDIUM),
        (_CREDENTIAL, "CONTENT_CREDENTIAL", "Credential solicitation", Severity.MEDIUM),
    )
    for terms, rule_id, title, severity in checks:
        hit = next((t for t in terms if t in lowered), None)
        if hit:
            out.append(
                RawFinding(
                    group=FindingGroup.CONTENT,
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    detail="Deterministic lexical marker. The semantic intent layer "
                    "(Phase 7) supersedes this; both are capped at the same 12 "
                    "points, because a real executive also writes urgent "
                    "confidential payment requests.",
                    evidence_quote=quote_for(hit)[:500],
                )
            )
    return out
