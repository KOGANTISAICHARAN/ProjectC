"""The case: the unit of value in this product.

A verdict is one field on a case, not the point of it. Everything here exists so
that a third party can re-derive the verdict from the evidence.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import (
    AiCallKind,
    ArtifactSource,
    AuthMechanism,
    AuthResult,
    Band,
    CaseStatus,
    Classification,
    FindingGroup,
    HopRole,
    IndicatorType,
    IpClass,
    ParseStatus,
    Severity,
    TrustState,
)
from app.models.mixins import (
    CreatedAt,
    OrgScoped,
    Timestamped,
    UUIDPrimaryKey,
    enum_check,
    enum_column,
)


class Case(OrgScoped, UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "cases"
    __table_args__ = (
        UniqueConstraint("org_id", "case_ref", name="uq_cases_org_id_case_ref"),
        CheckConstraint("score IS NULL OR (score >= 0 AND score <= 100)", name="score_range"),
        CheckConstraint(
            "data_completeness IS NULL OR (data_completeness >= 0 AND data_completeness <= 8)",
            name="completeness_range",
        ),
        Index("ix_cases_org_created", "org_id", "created_at"),
        Index("ix_cases_org_score", "org_id", "score"),
    )

    #: Human-facing identifier, e.g. CASE-2026-0143. Unique per org, not global:
    #: analysts quote it aloud and in reports.
    case_ref: Mapped[str] = mapped_column(String(32), nullable=False)

    status: Mapped[CaseStatus] = mapped_column(
        enum_column(CaseStatus), nullable=False, server_default=CaseStatus.RECEIVED.value
    )
    score: Mapped[int | None] = mapped_column(SmallInteger)
    band: Mapped[Band | None] = mapped_column(enum_column(Band))
    classification: Mapped[Classification | None] = mapped_column(enum_column(Classification))

    #: How many of the eight signal groups actually produced data. A case scored
    #: from 5 of 8 groups is not the same evidence as one scored from 8, and the
    #: UI must never present them as equivalent.
    data_completeness: Mapped[int | None] = mapped_column(SmallInteger)

    #: Which weights file produced ``score``. Recorded so a re-run years later is
    #: comparable, and cited in the evidence chain.
    weights_version: Mapped[str | None] = mapped_column(String(32))

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)

    artifacts: Mapped[list[EmailArtifact]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class EmailArtifact(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """The original bytes, hashed before anything touched them."""

    __tablename__ = "email_artifacts"
    __table_args__ = (
        # The same message submitted twice within an org is the same evidence.
        UniqueConstraint("org_id", "sha256", name="uq_email_artifacts_org_id_sha256"),
        CheckConstraint("size_bytes > 0", name="size_positive"),
        CheckConstraint("char_length(sha256) = 64", name="sha256_length"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )

    #: Object-storage key. The blob itself is write-once and is reachable only
    #: through short-lived signed URLs; every download emits an evidence event.
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)

    #: SHA-256 of the raw bytes, computed BEFORE parsing. This is the anchor the
    #: entire chain of custody hangs from.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    filename: Mapped[str | None] = mapped_column(String(512))

    source: Mapped[ArtifactSource] = mapped_column(
        enum_column(ArtifactSource), nullable=False, server_default=ArtifactSource.UPLOAD.value
    )
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acquired_by: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    parse_status: Mapped[ParseStatus] = mapped_column(
        enum_column(ParseStatus), nullable=False, server_default=ParseStatus.PENDING.value
    )

    #: Set when retention expires. The row survives with its hashes so the
    #: evidence chain stays verifiable after the content is gone.
    content_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    case: Mapped[Case] = relationship(back_populates="artifacts")


class EmailHeader(OrgScoped, UUIDPrimaryKey, Base):
    """Every header, in the order it appeared.

    ``ordinal`` looks trivial and is not: header *emission order* is a stable
    fingerprint of the sending toolchain and is locus M of Email DNA (Phase 6).
    Storing headers as an unordered map would destroy it.
    """

    __tablename__ = "email_headers"
    __table_args__ = (Index("ix_email_headers_case_ordinal", "case_id", "ordinal"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    value_raw: Mapped[str] = mapped_column(Text, nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)

    #: True for the 2nd and subsequent occurrence of a header that RFC 5322
    #: permits only once. A duplicate From is both an RFC violation and a real
    #: attack: some clients render the first, some filters evaluate the last.
    is_duplicate: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    #: Whether this header sits above the trust boundary. An injected
    #: Authentication-Results below it is evidence of evasion, not a result.
    above_boundary: Mapped[bool | None] = mapped_column(Boolean)


class ReceivedHop(OrgScoped, UUIDPrimaryKey, Base):
    """One Received header, decomposed.

    The two halves have completely different trust properties: ``helo`` is free
    text supplied by the connecting client and is worthless alone, while
    ``observed_ip`` is the receiving MTA's own record of the TCP peer and is
    trustworthy exactly to the degree that the receiving MTA is.
    """

    __tablename__ = "received_hops"
    __table_args__ = (
        UniqueConstraint("case_id", "seq", name="uq_received_hops_case_id_seq"),
        Index("ix_received_hops_observed_ip", "observed_ip"),
        Index("ix_received_hops_org_asn", "org_id", "asn"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: 0 = topmost header = most recent = most trusted.
    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    helo: Mapped[str | None] = mapped_column(String(512))  # client-asserted
    rdns_claim: Mapped[str | None] = mapped_column(String(512))  # receiver-observed
    observed_ip: Mapped[str | None] = mapped_column(INET)  # receiver-observed
    by_host: Mapped[str | None] = mapped_column(String(512))
    protocol: Mapped[str | None] = mapped_column(String(64))
    tls_info: Mapped[str | None] = mapped_column(String(256))
    hop_ts_utc: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    ip_class: Mapped[IpClass] = mapped_column(
        enum_column(IpClass), nullable=False, server_default=IpClass.UNKNOWN.value
    )
    role: Mapped[HopRole] = mapped_column(
        enum_column(HopRole), nullable=False, server_default=HopRole.EXTERNAL.value
    )
    trust_state: Mapped[TrustState] = mapped_column(
        enum_column(TrustState), nullable=False, server_default=TrustState.ASSERTED.value
    )

    asn: Mapped[int | None] = mapped_column(Integer)
    asn_org: Mapped[str | None] = mapped_column(String(256))
    country: Mapped[str | None] = mapped_column(String(2))  # ISO-3166-1 alpha-2, country only
    net_type: Mapped[str | None] = mapped_column(String(32))  # datacenter|residential|mobile|vpn

    #: Integrity defects found on this hop: non-monotonic timestamp, broken
    #: handoff continuity, impossible positioning.
    anomalies: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")


class AuthResultRow(OrgScoped, UUIDPrimaryKey, Base):
    """SPF / DKIM / DMARC / ARC, as reported *and* as recomputed.

    Both are stored because they answer different questions. ``result_reported``
    is what our own MTA concluded at delivery time and is authoritative for SPF.
    ``result_recomputed`` is what we can verify now, which for DKIM is
    cryptographic and for SPF is only corroborating -- DNS may have changed.
    """

    __tablename__ = "auth_results"
    __table_args__ = (Index("ix_auth_results_case_mechanism", "case_id", "mechanism"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    mechanism: Mapped[AuthMechanism] = mapped_column(enum_column(AuthMechanism), nullable=False)
    result_reported: Mapped[AuthResult | None] = mapped_column(
        enum_column(AuthResult, name="auth_result_reported")
    )
    result_recomputed: Mapped[AuthResult | None] = mapped_column(
        enum_column(AuthResult, name="auth_result_recomputed")
    )

    #: The authserv-id of the Authentication-Results header this came from.
    #: Only results from an authserv-id we recognise are trusted; the presence of
    #: any other is itself a malicious indicator.
    authserv_id: Mapped[str | None] = mapped_column(String(256))
    trusted_source: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    #: DMARC alignment to the RFC5322.From domain. This -- not the pass/fail
    #: above -- is what speaks about the identity a human actually reads.
    aligned: Mapped[bool | None] = mapped_column(Boolean)

    selector: Mapped[str | None] = mapped_column(String(128))
    d_domain: Mapped[str | None] = mapped_column(String(253))
    h_tags: Mapped[str | None] = mapped_column(Text)  # which headers were signed
    l_tag: Mapped[int | None] = mapped_column(Integer)  # body-length limit: weakens the sig
    policy: Mapped[str | None] = mapped_column(String(64))  # none|quarantine|reject

    #: Human-readable caveat surfaced verbatim in the UI, e.g. "selector key no
    #: longer published; signature cannot be verified".
    caveat: Mapped[str | None] = mapped_column(Text)


class OriginAssessment(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """The product's centrepiece: how far upstream the evidence actually reaches.

    Deliberately one row per case with a ``claim_text`` column: the sentence the
    UI and the PDF render is generated once, here, from the claim contract --
    never assembled ad hoc in a template where it could drift into overclaiming.
    """

    __tablename__ = "origin_assessment"
    __table_args__ = (
        UniqueConstraint("case_id", name="uq_origin_assessment_case_id"),
        CheckConstraint("confidence >= 0 AND confidence <= 95", name="confidence_never_certain"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )

    #: First Externally Observed Sender: the peer IP the earliest MTA we trust
    #: recorded. NULL when no trustworthy receiving infrastructure was found --
    #: refusing to answer is a feature.
    feos_ip: Mapped[str | None] = mapped_column(INET)
    feos_prefix: Mapped[str | None] = mapped_column(CIDR)
    feos_asn: Mapped[int | None] = mapped_column(Integer)
    feos_org: Mapped[str | None] = mapped_column(String(256))
    feos_country: Mapped[str | None] = mapped_column(String(2))
    net_type: Mapped[str | None] = mapped_column(String(32))

    boundary_hop_seq: Mapped[int | None] = mapped_column(Integer)

    #: Capped at 95 by a check constraint. Never 100: certainty is not available
    #: from header evidence, and claiming it would be the first thing a judge or
    #: an opposing expert attacks.
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")

    #: Every additive factor, named, so the UI can show the arithmetic.
    confidence_breakdown: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )

    geo_dataset: Mapped[str | None] = mapped_column(String(64))
    geo_version: Mapped[str | None] = mapped_column(String(64))

    #: Geolocation is evaluated as of the MESSAGE date, not today. IP
    #: allocations move; a lookup today can attribute a 2024 message to whoever
    #: holds the range now.
    evaluated_for_date: Mapped[date | None] = mapped_column()

    claim_text: Mapped[str | None] = mapped_column(Text)


class Indicator(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("case_id", "type", "normalised", name="uq_indicators_case_type_norm"),
        # The pivot query -- "where else have we seen this?" -- is the one
        # analysts live in, so it gets a dedicated composite index.
        Index("ix_indicators_org_type_norm", "org_id", "type", "normalised"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[IndicatorType] = mapped_column(enum_column(IndicatorType), nullable=False)

    value: Mapped[str] = mapped_column(Text, nullable=False)
    #: Lowercased, punycode-decoded, defanged-form resolved, IPv6 expanded.
    #: All matching happens on this column; ``value`` is kept verbatim for
    #: evidence.
    normalised: Mapped[str] = mapped_column(Text, nullable=False)
    registrable_domain: Mapped[str | None] = mapped_column(String(253), index=True)

    #: Discriminative power, -log(df/N). Recomputed as the corpus grows.
    #: Low-IDF indicators (gmail.com, hyperscaler ASNs, URL shorteners) are shown
    #: as context but never counted as campaign linkage evidence.
    idf: Mapped[float | None] = mapped_column(Numeric(6, 3))
    is_hub: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")


class Finding(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """One scored observation.

    Every point of the 0-100 risk score traces to a row here, and every row
    carries the rule that produced it and the evidence it rests on. This table
    is what makes the score arguable rather than assertable.
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_case_group", "case_id", "signal_group"),
        # The scoring engine sums contributions per group; an unrecognised group
        # would silently drop points out of the total.
        enum_check("signal_group", FindingGroup, "signal_group_vocab"),
        CheckConstraint(
            "score_contribution >= -100 AND score_contribution <= 100",
            name="contribution_range",
        ),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    #: Named `signal_group`, not `group`: GROUP is a reserved word in SQL and a
    #: column called that must be quoted in every hand-written query forever.
    signal_group: Mapped[FindingGroup] = mapped_column(enum_column(FindingGroup), nullable=False)

    #: Stable identifier such as AUTH_DMARC_UNALIGNED. Referenced by the MITRE
    #: mapping and by the report, so it must not change once released.
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)

    #: Negative values are permitted: the legitimacy dampener is a finding too,
    #: and must be as visible as anything that raises the score.
    score_contribution: Mapped[float] = mapped_column(Numeric(6, 2), nullable=False)

    #: One sentence a non-specialist can act on. The UI leads with this and keeps
    #: ``detail`` behind a toggle: the technical account is what survives an
    #: expert challenge, but it is not what a reader should meet first.
    plain_summary: Mapped[str | None] = mapped_column(Text)

    #: Where to look in the artifact -- a header name, a hop seq, an indicator id.
    evidence_ref: Mapped[str | None] = mapped_column(String(300))

    #: For content findings, the verbatim substring of the body. Validated
    #: against the artifact before the finding is persisted; a quote that cannot
    #: be located means the finding is discarded.
    evidence_quote: Mapped[str | None] = mapped_column(Text)

    confidence: Mapped[float | None] = mapped_column(Numeric(4, 3))
    mitre_technique: Mapped[str | None] = mapped_column(String(32))

    case: Mapped[Case] = relationship(back_populates="findings")


class AiAnalysis(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """A record of exactly which analytic produced a finding.

    Model id, prompt version and both hashes are stored so a reviewer can re-run
    the identical call years later. These fields are also written into the
    evidence chain: reproducibility is the forensic bar, and an un-versioned
    model call cannot meet it.
    """

    __tablename__ = "ai_analysis"
    __table_args__ = (Index("ix_ai_analysis_case_kind", "case_id", "call_kind"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    call_kind: Mapped[AiCallKind] = mapped_column(enum_column(AiCallKind), nullable=False)

    model_id: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    #: The live hallucination metric. Every AI finding must quote the body
    #: verbatim; quotes that cannot be located are dropped before scoring, and
    #: the ratio of dropped to validated is surfaced on the dashboard.
    quotes_validated: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    quotes_dropped: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    prompt_injection_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    tokens: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    cached: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
