"""Controlled vocabularies.

Every one of these is rendered as ``VARCHAR + CHECK`` rather than a native
Postgres ``ENUM``. Native enums cannot have values removed and can only gain
values at the end, which turns a routine vocabulary change into a table rewrite.
A check constraint is altered with one statement.

These vocabularies are closed on purpose: the AI layer (Phase 7) is constrained
to exactly these values, so anything it returns is either a member of the set or
is rejected before it can reach a score.
"""

from __future__ import annotations

from enum import StrEnum


class MembershipRole(StrEnum):
    OWNER = "owner"
    ANALYST = "analyst"
    VIEWER = "viewer"


class CaseStatus(StrEnum):
    RECEIVED = "received"  # artifact stored and hashed, nothing parsed yet
    ANALYSING = "analysing"  # Band A running
    ENRICHING = "enriching"  # Band A done, Band B in flight
    COMPLETE = "complete"
    FAILED = "failed"


class Band(StrEnum):
    """Risk bands. Thresholds live in scoring/weights.yaml, not here."""

    BENIGN = "benign"  #  0-19
    SUSPICIOUS = "suspicious"  # 20-39
    LIKELY_MALICIOUS = "likely_malicious"  # 40-64
    HIGH = "high"  # 65-84
    CRITICAL = "critical"  # 85-100


class Classification(StrEnum):
    """Derived from *which* signal groups fired, never from the score alone."""

    BENIGN = "benign"
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    BEC = "bec"
    CREDENTIAL_PHISHING = "credential_phishing"
    IMPERSONATION = "impersonation"
    MALWARE_DELIVERY = "malware_delivery"
    EXTORTION = "extortion"
    UNKNOWN = "unknown"


class ArtifactSource(StrEnum):
    UPLOAD = "upload"
    EXTENSION = "extension"
    API = "api"


class ParseStatus(StrEnum):
    PENDING = "pending"
    PARSED = "parsed"
    MALFORMED = "malformed"  # parsed with recoverable defects
    REJECTED = "rejected"  # unsafe or unparseable; see failure_reason


class IpClass(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"  # RFC1918, ULA
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    CGNAT = "cgnat"  # 100.64.0.0/10
    RESERVED = "reserved"
    UNKNOWN = "unknown"


class HopRole(StrEnum):
    """How much a Received hop's testimony is worth. See docs/CLAIM_CONTRACT.md."""

    ORG_INTERNAL = "org_internal"
    TRUSTED_PROVIDER = "trusted_provider"
    KNOWN_FORWARDER = "known_forwarder"
    EXTERNAL = "external"


class TrustState(StrEnum):
    VOUCHED = "vouched"  # at or above the trust boundary
    BOUNDARY = "boundary"  # the last hop we vouch for
    ASSERTED = "asserted"  # below the boundary: the sender's own claim
    FORGED = "forged"  # asserted AND internally inconsistent


class AuthMechanism(StrEnum):
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    ARC = "arc"


class AuthResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    # Distinct from FAIL on purpose: a DKIM selector whose key has since rotated
    # cannot be verified, and reporting that as a failure is a forensic error.
    INDETERMINATE = "indeterminate"


class IndicatorType(StrEnum):
    IP = "ip"
    NET_PREFIX = "net_prefix"
    DOMAIN = "domain"
    HOST = "host"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    ASN = "asn"
    MESSAGE_ID = "message_id"


class FindingGroup(StrEnum):
    """The eight scoring groups. Weights live in scoring/weights.yaml."""

    AUTHENTICATION = "authentication"
    IDENTITY = "identity"
    INFRASTRUCTURE = "infrastructure"
    URL_DOMAIN = "url_domain"
    CONTENT = "content"  # the only group the AI layer contributes to
    ATTACHMENT = "attachment"
    THREAT_INTEL = "threat_intel"
    CAMPAIGN = "campaign"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AiCallKind(StrEnum):
    EXTRACT = "extract"  # scored; strict schema; runs on every case
    NARRATIVE = "narrative"  # unscored prose; gated on score >= 40


class NodeType(StrEnum):
    EMAIL = "email"
    SENDER_ADDRESS = "sender_address"
    REPLY_TO_ADDRESS = "reply_to_address"
    DISPLAY_NAME = "display_name"
    DOMAIN = "domain"
    HOST = "host"
    URL = "url"
    IP = "ip"
    NET_PREFIX = "net_prefix"
    ASN = "asn"
    ATTACHMENT_HASH = "attachment_hash"
    DKIM_IDENTITY = "dkim_identity"
    TOOL_FINGERPRINT = "tool_fingerprint"
    CAMPAIGN = "campaign"


class EdgeType(StrEnum):
    SENT_FROM = "sent_from"
    OBSERVED_AT = "observed_at"
    REPLIES_TO = "replies_to"
    CONTAINS_URL = "contains_url"
    CONTAINS_ATTACHMENT = "contains_attachment"
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    ANNOUNCED_BY = "announced_by"
    SIGNED_BY = "signed_by"
    USES_TOOL = "uses_tool"
    SIMILAR_TO = "similar_to"
    MEMBER_OF = "member_of"


class JobKind(StrEnum):
    """Work that runs on the queue.

    Only kinds with a registered handler AND an enqueue site belong here.
    Fingerprinting, campaign linkage, enrichment and the AI layer all run inline
    during ingest: none of them blocks on something slow enough to justify a
    round trip through the queue, and declaring enum members with no handler
    advertises capability the system does not have.
    """

    GENERATE_REPORT = "generate_report"


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    DEAD = "dead"  # exhausted max_attempts


class EvidenceAction(StrEnum):
    """Chain-of-custody events. Analyst actions are events too: custody covers
    humans, not only pipelines."""

    ACQUIRED = "acquired"
    PARSED = "parsed"
    AUTH_EVALUATED = "auth_evaluated"
    ORIGIN_RECONSTRUCTED = "origin_reconstructed"
    ENRICHED = "enriched"
    AI_ANALYSED = "ai_analysed"
    SCORED = "scored"
    CAMPAIGN_LINKED = "campaign_linked"
    ANALYST_NOTE = "analyst_note"
    CASE_VIEWED = "case_viewed"
    ARTIFACT_DOWNLOADED = "artifact_downloaded"
    REPORT_GENERATED = "report_generated"
    EVIDENCE_VERIFIED = "evidence_verified"
