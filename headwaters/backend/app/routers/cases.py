"""Case endpoints.

Routers contain no logic: they validate, authorise, call a service, and
serialise. Every session comes from ``get_tenant_db``, so row-level security
applies to each statement -- a router must never reach the privileged system
connection, and a test enforces that.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.enums import ArtifactSource
from app.security.deps import get_tenant_db
from app.security.identity import DEMO_ORG_ID, resolve_user_id
from app.services.ingest import ingest_email

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["cases"])


def tenant_session(
    user_id: Annotated[uuid.UUID, Depends(resolve_user_id)],
) -> Any:
    yield from get_tenant_db(user_id)


TenantDb = Annotated[Session, Depends(tenant_session)]
UserId = Annotated[uuid.UUID, Depends(resolve_user_id)]


# --------------------------------------------------------------- schemas ---
class CaseSummary(BaseModel):
    id: uuid.UUID
    case_ref: str
    status: str
    score: int | None
    band: str | None
    classification: str | None
    data_completeness: int | None
    subject: str | None = None
    from_address: str | None = None
    created_at: str


class HopOut(BaseModel):
    seq: int
    helo: str | None
    rdns_claim: str | None
    observed_ip: str | None
    by_host: str | None
    ip_class: str
    role: str
    trust_state: str
    hop_ts_utc: str | None
    anomalies: list[str] = Field(default_factory=list)
    asn: int | None = None
    asn_org: str | None = None
    #: ISO-3166-1 alpha-2. Country granularity only, by design.
    country: str | None = None
    net_type: str | None = None


class FindingOut(BaseModel):
    signal_group: str
    rule_id: str
    severity: str
    title: str
    #: Plain sentence for the reader; `detail` is the technical account.
    plain_summary: str | None = None
    detail: str | None
    score_contribution: float
    evidence_ref: str | None
    evidence_quote: str | None
    mitre_technique: str | None


class OriginOut(BaseModel):
    feos_ip: str | None
    boundary_hop_seq: int | None
    confidence: int
    confidence_breakdown: dict[str, int]
    claim_text: str | None
    geo_dataset: str | None
    #: Explicit rather than inferred from a null: "we did not look" and "we
    #: looked and found nothing" must not render identically.
    geo_available: bool


class AuthOut(BaseModel):
    mechanism: str
    result_reported: str | None
    authserv_id: str | None
    trusted_source: bool
    aligned: bool | None
    d_domain: str | None
    caveat: str | None


class CaseDetail(CaseSummary):
    weights_version: str | None
    reply_to: str | None
    return_path: str | None
    message_id: str | None
    body_preview: str | None
    hops: list[HopOut]
    findings: list[FindingOut]
    auth_results: list[AuthOut]
    origin: OriginOut | None
    group_contributions: dict[str, float]
    urls: list[str]
    attachments: list[dict[str, Any]]


# ----------------------------------------------------------------- routes ---
class ExtensionIngest(BaseModel):
    """Payload from the browser extension.

    ``raw`` is the COMPLETE RFC 5322 message, base64url-encoded exactly as Gmail
    returns it. Not the rendered body: scraping the DOM loses every Received
    header, and with them origin reconstruction, the trust boundary and the
    infrastructure locus of Email DNA.
    """

    raw: str = Field(description="base64url-encoded RFC 5322 message")
    message_id: str | None = Field(default=None, description="Gmail message id, for idempotency")
    #: True when this is the bundled demonstration fixture rather than a real
    #: message. The verdict card must say so: a security warning with no visible
    #: subject or sender reads as a judgement on whatever the user is looking at.
    is_sample: bool = Field(default=False)


@router.post("/cases/from-extension", status_code=status.HTTP_201_CREATED)
def create_case_from_extension(
    payload: ExtensionIngest, db: TenantDb, user_id: UserId
) -> dict[str, Any]:
    """Ingest a message captured by the browser extension."""
    import base64
    import binascii

    settings = get_settings()
    encoded = payload.raw
    try:
        # Gmail returns base64url. Padding is restored because Gmail strips it.
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="raw must be base64url-encoded RFC 5322",
        ) from exc

    if not decoded:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty message")
    if len(decoded) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Message exceeds {settings.max_upload_bytes} bytes",
        )

    outcome = ingest_email(
        db,
        decoded,
        org_id=DEMO_ORG_ID,
        user_id=user_id,
        filename=payload.message_id,
        source=ArtifactSource.EXTENSION,
    )
    db.flush()

    fusion = outcome.analysis.fusion
    origin = outcome.analysis.origin

    case_id = outcome.duplicate_of or outcome.case_id
    case_ref = outcome.case_ref
    if outcome.duplicate_of is not None:
        # Re-checking the same message must still name the case, or the link the
        # employee is given has no identity to quote to their security team.
        case_ref = (
            db.execute(
                text("SELECT case_ref FROM cases WHERE id = :id"), {"id": str(case_id)}
            ).scalar()
            or ""
        )

    # The extension shows ONE sentence to a non-analyst. It is composed here so
    # the wording obeys the claim contract, rather than being assembled in
    # JavaScript where it could drift into overclaiming.
    return {
        "case_id": str(case_id),
        "case_ref": case_ref,
        "duplicate": outcome.duplicate_of is not None,
        "score": fusion.score,
        "band": fusion.band.value,
        "classification": fusion.classification.value,
        "headline": _headline(fusion.band.value, fusion.classification.value),
        "advice": _advice(fusion.band.value),
        # The extension shows this instead of the internal band name.
        "band_label": _PLAIN_BAND.get(fusion.band.value, fusion.band.value),
        "origin_confidence": origin.confidence,
        "feos_ip": origin.feos_ip,
        # Echoed back so the extension can state WHAT it analysed. Without this
        # the card is a verdict with no subject, which the reader reasonably
        # attributes to whatever is on screen.
        "subject": outcome.analysis.parsed.subject,
        "from_address": outcome.analysis.from_address,
        "is_sample": payload.is_sample,
    }


#: Plain-English names for the employee-facing door. An office worker being
#: told "Likely BEC" learns nothing; the analyst dashboard keeps the technical
#: label, because the two audiences need different words for the same finding.
_PLAIN_LABEL = {
    "bec": "someone impersonating a colleague to request a payment",
    "credential_phishing": "a fake sign-in page trying to steal your password",
    "spear_phishing": "a targeted scam written specifically for you",
    "phishing": "a scam email",
    "impersonation": "someone pretending to be a person you know",
    "malware_delivery": "an attachment that may be harmful",
    "extortion": "a threat or blackmail attempt",
    "unknown": "something suspicious",
}


def _headline(band: str, classification: str) -> str:
    if band == "benign":
        return "No threat indicators found in this message."
    label = _PLAIN_LABEL.get(classification, "something suspicious")
    if band in ("critical", "high"):
        return f"This looks like {label}. Do not act on it."
    return f"This may be {label}. Treat it with caution."


#: What a non-specialist sees instead of the internal band name. "Likely
#: malicious" and "credential phishing" are analyst vocabulary; the person
#: deciding whether to click a link needs a verdict, not a taxonomy.
_PLAIN_BAND: dict[str, str] = {
    "benign": "Looks safe",
    "suspicious": "Be careful",
    "likely_malicious": "Probably an attack",
    "high": "Almost certainly an attack",
    "critical": "Dangerous",
}


def _advice(band: str) -> str:
    """One instruction the reader can act on immediately.

    Deliberately short. Advice that runs to three sentences is advice nobody
    finishes reading, and this is the only text between a person and a link.
    """
    if band == "benign":
        return "Nothing to do."
    if band in ("critical", "high"):
        return (
            "Do not reply, click anything, or pay anything. If it claims to be "
            "someone you know, phone them on a number you already have — not one "
            "from this email."
        )
    return "Do not click any link in this email until someone has checked it."


@router.post("/cases", status_code=status.HTTP_201_CREATED)
def create_case(
    db: TenantDb,
    user_id: UserId,
    file: Annotated[UploadFile | None, File()] = None,
    raw_email: Annotated[str | None, Form()] = None,
) -> dict[str, Any]:
    """Ingest one `.eml` (multipart) or a pasted raw message (form field).

    Band A runs synchronously with no outbound network calls, so a verdict is
    returned on this response. Band B enrichment is queued separately.
    """
    settings = get_settings()

    if file is not None:
        payload = file.file.read(settings.max_upload_bytes + 1)
        filename = file.filename
    elif raw_email:
        payload = raw_email.encode("utf-8", errors="replace")
        filename = "pasted-headers.eml"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide a .eml file or a raw_email field",
        )

    if not payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty message")
    if len(payload) > settings.max_upload_bytes:
        # Enforced before anything parses it: a size check that happens after
        # buffering has already lost the argument.
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Message exceeds {settings.max_upload_bytes} bytes",
        )

    outcome = ingest_email(
        db,
        payload,
        org_id=DEMO_ORG_ID,
        user_id=user_id,
        filename=filename,
        source=ArtifactSource.UPLOAD,
    )
    db.flush()

    if outcome.duplicate_of is not None:
        return {
            "case_id": str(outcome.duplicate_of),
            "duplicate": True,
            "sha256": outcome.sha256,
            "message": "Identical bytes already analysed; returning the existing case.",
        }

    fusion = outcome.analysis.fusion
    return {
        "case_id": str(outcome.case_id),
        "case_ref": outcome.case_ref,
        "sha256": outcome.sha256,
        "duplicate": False,
        "verdict": {
            "score": fusion.score,
            "band": fusion.band.value,
            "classification": fusion.classification.value,
            "data_completeness": fusion.data_completeness,
            "controls_applied": fusion.controls_applied,
        },
    }


@router.get("/cases", response_model=list[CaseSummary])
def list_cases(db: TenantDb, limit: int = 50) -> list[CaseSummary]:
    rows = db.execute(
        text(
            """
            SELECT c.id, c.case_ref, c.status, c.score, c.band, c.classification,
                   c.data_completeness, c.created_at,
                   (SELECT value_raw FROM email_headers h
                     WHERE h.case_id = c.id AND lower(h.name) = 'subject' LIMIT 1),
                   (SELECT value_raw FROM email_headers h
                     WHERE h.case_id = c.id AND lower(h.name) = 'from' LIMIT 1)
              FROM cases c
             ORDER BY c.created_at DESC
             LIMIT :limit
            """
        ),
        {"limit": min(limit, 200)},
    ).all()

    return [
        CaseSummary(
            id=r[0],
            case_ref=r[1],
            status=r[2],
            score=r[3],
            band=r[4],
            classification=r[5],
            data_completeness=r[6],
            created_at=r[7].isoformat(),
            subject=r[8],
            from_address=r[9],
        )
        for r in rows
    ]


class CampaignLinkOut(BaseModel):
    case_id: uuid.UUID
    case_ref: str
    score: int | None
    dna_score: float
    locus_breakdown: dict[str, float]
    shared_indicators: list[str]


class CampaignOut(BaseModel):
    id: uuid.UUID
    name: str
    summary: str | None
    member_count: int
    max_score: int | None
    first_seen: str | None
    last_seen: str | None
    barcode: str | None
    members: list[CampaignLinkOut]
    #: Printed in the UI verbatim. A linkage is a hypothesis about tooling, not
    #: a claim about who is behind it.
    caveat: str = (
        "Operational linkage hypothesis, not attribution. Shared tooling can indicate "
        "one actor, one purchased phishing kit, or one phishing-as-a-service platform "
        "used by many unrelated actors."
    )


def _require_case(db: Session, case_id: uuid.UUID) -> None:
    """404 for both "absent" and "belongs to another organisation".

    Row-level security filters the second case out, so the two are
    indistinguishable to the caller. That is deliberate: a 403 would confirm the
    identifier exists.
    """
    found = db.execute(text("SELECT 1 FROM cases WHERE id = :id"), {"id": str(case_id)}).first()
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")


@router.get("/cases/{case_id}/headers")
def get_headers(case_id: uuid.UUID, db: TenantDb) -> dict[str, Any]:
    """Every header in emission order, with duplicates preserved.

    Order is not cosmetic: it is Email DNA locus M, and duplicates are evidence
    -- two From headers is an RFC violation and a real attack.
    """
    _require_case(db, case_id)
    rows = db.execute(
        text(
            "SELECT ordinal, name, value_raw, is_duplicate, above_boundary "
            "FROM email_headers WHERE case_id = :id ORDER BY ordinal"
        ),
        {"id": str(case_id)},
    ).all()
    return {
        "headers": [
            {
                "ordinal": r[0],
                "name": r[1],
                "value": r[2],
                "is_duplicate": r[3],
                "above_boundary": r[4],
            }
            for r in rows
        ],
        "note": (
            "Emission order is preserved verbatim. Duplicate headers are retained: "
            "some mail clients render the first occurrence while some filters "
            "evaluate the last, so a disagreement between them is itself a finding."
        ),
    }


@router.get("/cases/{case_id}/origin", response_model=OriginOut)
def get_origin(case_id: uuid.UUID, db: TenantDb) -> OriginOut:
    """The trust-boundary assessment and the arithmetic behind its confidence."""
    _require_case(db, case_id)
    row = db.execute(
        text(
            "SELECT feos_ip, boundary_hop_seq, confidence, confidence_breakdown, "
            "claim_text, geo_dataset FROM origin_assessment WHERE case_id = :id"
        ),
        {"id": str(case_id)},
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No origin assessment")
    return OriginOut(
        feos_ip=str(row[0]) if row[0] else None,
        boundary_hop_seq=row[1],
        confidence=row[2],
        confidence_breakdown=row[3] or {},
        claim_text=row[4],
        geo_dataset=row[5],
        geo_available=row[5] is not None,
    )


@router.get("/cases/{case_id}/hops", response_model=list[HopOut])
def get_hops(case_id: uuid.UUID, db: TenantDb) -> list[HopOut]:
    """Map-ready hop list.

    Named `/hops`, never `/route`: the Received chain records hosts that handled
    the message, not a path it travelled. The API vocabulary has to match the
    claim contract, or the misstatement reaches the UI through the field name.
    """
    _require_case(db, case_id)
    rows = db.execute(
        text(
            "SELECT seq, helo, rdns_claim, observed_ip, by_host, ip_class, role, "
            "trust_state, hop_ts_utc, anomalies, asn, asn_org, country, net_type "
            "FROM received_hops WHERE case_id = :id ORDER BY seq"
        ),
        {"id": str(case_id)},
    ).all()
    return [
        HopOut(
            seq=r[0],
            helo=r[1],
            rdns_claim=r[2],
            observed_ip=str(r[3]) if r[3] else None,
            by_host=r[4],
            ip_class=r[5],
            role=r[6],
            trust_state=r[7],
            hop_ts_utc=r[8].isoformat() if r[8] else None,
            anomalies=r[9] or [],
            asn=r[10],
            asn_org=r[11],
            country=r[12],
            net_type=r[13],
        )
        for r in rows
    ]


@router.get("/cases/{case_id}/findings", response_model=list[FindingOut])
def get_findings(case_id: uuid.UUID, db: TenantDb, group: str | None = None) -> list[FindingOut]:
    """The drill-down behind the score. Every point traces to a row here."""
    _require_case(db, case_id)
    clause = "AND signal_group = :group" if group else ""
    params: dict[str, Any] = {"id": str(case_id)}
    if group:
        params["group"] = group
    rows = db.execute(
        text(
            f"""
            SELECT signal_group, rule_id, severity, title, detail, plain_summary,
                   score_contribution, evidence_ref, evidence_quote, mitre_technique
              FROM findings WHERE case_id = :id {clause}
             ORDER BY score_contribution DESC
            """  # noqa: S608 - clause is a literal; group is bound
        ),
        params,
    ).all()
    return [
        FindingOut(
            signal_group=r[0],
            rule_id=r[1],
            severity=r[2],
            title=r[3],
            detail=r[4],
            plain_summary=r[5],
            score_contribution=float(r[6]),
            evidence_ref=r[7],
            evidence_quote=r[8],
            mitre_technique=r[9],
        )
        for r in rows
    ]


@router.get("/cases/{case_id}/score")
def get_score(case_id: uuid.UUID, db: TenantDb) -> dict[str, Any]:
    """Score with its per-group derivation and the MITRE techniques that fired.

    Weights and thresholds are returned alongside the result so a reader can
    re-derive the number rather than take it on trust.
    """
    from app.services.scoring.fusion import load_weights

    case = db.execute(
        text(
            "SELECT score, band, classification, data_completeness, weights_version "
            "FROM cases WHERE id = :id"
        ),
        {"id": str(case_id)},
    ).first()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    rows = db.execute(
        text(
            "SELECT signal_group, sum(score_contribution), count(*), "
            "       array_agg(DISTINCT mitre_technique) FILTER (WHERE mitre_technique IS NOT NULL) "
            "  FROM findings WHERE case_id = :id GROUP BY signal_group"
        ),
        {"id": str(case_id)},
    ).all()

    config = load_weights()
    mitre: set[str] = set()
    groups = []
    for group, contribution, count, techniques in rows:
        mitre.update(techniques or [])
        groups.append(
            {
                "group": group,
                "contribution": round(float(contribution), 2),
                "max_weight": config["groups"].get(group),
                "finding_count": count,
            }
        )

    return {
        "score": case[0],
        "band": case[1],
        "classification": case[2],
        "data_completeness": case[3],
        "weights_version": case[4],
        "groups": sorted(groups, key=lambda g: g["contribution"], reverse=True),
        "weights": config["groups"],
        "bands": config["bands"],
        "controls": config["controls"],
        "mitre_techniques": sorted(mitre),
        "note": (
            "Classification is derived from WHICH groups fired, not from the score "
            "alone: a score driven by attachments is a different animal from the "
            "same score driven by identity, and an analyst triages the label first."
        ),
    }


@router.get("/cases/{case_id}/campaign", response_model=CampaignOut | None)
def get_case_campaign(case_id: uuid.UUID, db: TenantDb) -> CampaignOut | None:
    """The campaign this case belongs to, with the evidence for each link."""
    row = db.execute(
        text(
            """
            SELECT c.id, c.name, c.summary, c.member_count, c.max_score,
                   c.first_seen, c.last_seen
              FROM campaigns c
              JOIN campaign_members m ON m.campaign_id = c.id
             WHERE m.case_id = :id
            """
        ),
        {"id": str(case_id)},
    ).first()
    if row is None:
        return None

    members = db.execute(
        text(
            """
            SELECT cs.id, cs.case_ref, cs.score, m.dna_score, m.locus_breakdown,
                   m.shared_indicators
              FROM campaign_members m
              JOIN cases cs ON cs.id = m.case_id
             WHERE m.campaign_id = :cid
             ORDER BY cs.created_at
            """
        ),
        {"cid": str(row[0])},
    ).all()

    barcode = db.execute(
        text("SELECT barcode FROM dna_fingerprints WHERE case_id = :id"),
        {"id": str(case_id)},
    ).scalar()

    return CampaignOut(
        id=row[0],
        name=row[1],
        summary=row[2],
        member_count=row[3],
        max_score=row[4],
        first_seen=row[5].isoformat() if row[5] else None,
        last_seen=row[6].isoformat() if row[6] else None,
        barcode=barcode,
        members=[
            CampaignLinkOut(
                case_id=m[0],
                case_ref=m[1],
                score=m[2],
                dna_score=float(m[3]),
                locus_breakdown={k: float(v) for k, v in (m[4] or {}).items()},
                shared_indicators=m[5] or [],
            )
            for m in members
        ],
    )


@router.get("/cases/{case_id}/dna")
def get_case_dna(case_id: uuid.UUID, db: TenantDb) -> dict[str, Any]:
    """The six loci and the barcode, for side-by-side comparison."""
    row = db.execute(
        text(
            "SELECT locus_i, locus_d, locus_n, locus_m, locus_c, locus_p, barcode, "
            "dna_version FROM dna_fingerprints WHERE case_id = :id"
        ),
        {"id": str(case_id)},
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No fingerprint")
    return {
        "loci": {"i": row[0], "d": row[1], "n": row[2], "m": row[3], "c": row[4], "p": row[5]},
        "barcode": row[6],
        "version": row[7],
        "locus_names": {
            "i": "infrastructure",
            "d": "identity",
            "n": "naming",
            "m": "tooling",
            "c": "content",
            "p": "payload",
        },
    }


@router.get("/cases/{case_id}", response_model=CaseDetail)
def get_case(case_id: uuid.UUID, db: TenantDb) -> CaseDetail:
    case = db.execute(
        text(
            """
            SELECT id, case_ref, status, score, band, classification,
                   data_completeness, weights_version, created_at
              FROM cases WHERE id = :id
            """
        ),
        {"id": str(case_id)},
    ).first()

    if case is None:
        # Also the response when the case belongs to another organisation: RLS
        # filters it out, so absence and denial are indistinguishable to the
        # caller. That is intentional -- a 403 would confirm the id exists.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    headers = {
        name.lower(): value
        for name, value in db.execute(
            text("SELECT name, value_raw FROM email_headers WHERE case_id = :id ORDER BY ordinal"),
            {"id": str(case_id)},
        ).all()
    }

    hops = [
        HopOut(
            seq=r[0],
            helo=r[1],
            rdns_claim=r[2],
            observed_ip=str(r[3]) if r[3] else None,
            by_host=r[4],
            ip_class=r[5],
            role=r[6],
            trust_state=r[7],
            hop_ts_utc=r[8].isoformat() if r[8] else None,
            anomalies=r[9] or [],
            asn=r[10],
            asn_org=r[11],
            country=r[12],
            net_type=r[13],
        )
        for r in db.execute(
            text(
                """
                SELECT seq, helo, rdns_claim, observed_ip, by_host, ip_class, role,
                       trust_state, hop_ts_utc, anomalies, asn, asn_org, country,
                       net_type
                  FROM received_hops WHERE case_id = :id ORDER BY seq
                """
            ),
            {"id": str(case_id)},
        ).all()
    ]

    findings = [
        FindingOut(
            signal_group=r[0],
            rule_id=r[1],
            severity=r[2],
            title=r[3],
            detail=r[4],
            plain_summary=r[5],
            score_contribution=float(r[6]),
            evidence_ref=r[7],
            evidence_quote=r[8],
            mitre_technique=r[9],
        )
        for r in db.execute(
            text(
                """
                SELECT signal_group, rule_id, severity, title, detail, plain_summary,
                       score_contribution, evidence_ref, evidence_quote, mitre_technique
                  FROM findings WHERE case_id = :id
                 ORDER BY score_contribution DESC
                """
            ),
            {"id": str(case_id)},
        ).all()
    ]

    auth_rows = [
        AuthOut(
            mechanism=r[0],
            result_reported=r[1],
            authserv_id=r[2],
            trusted_source=r[3],
            aligned=r[4],
            d_domain=r[5],
            caveat=r[6],
        )
        for r in db.execute(
            text(
                """
                SELECT mechanism, result_reported, authserv_id, trusted_source,
                       aligned, d_domain, caveat
                  FROM auth_results WHERE case_id = :id ORDER BY mechanism
                """
            ),
            {"id": str(case_id)},
        ).all()
    ]

    origin_row = db.execute(
        text(
            """
            SELECT feos_ip, boundary_hop_seq, confidence, confidence_breakdown,
                   claim_text, geo_dataset
              FROM origin_assessment WHERE case_id = :id
            """
        ),
        {"id": str(case_id)},
    ).first()

    origin = (
        OriginOut(
            feos_ip=str(origin_row[0]) if origin_row[0] else None,
            boundary_hop_seq=origin_row[1],
            confidence=origin_row[2],
            confidence_breakdown=origin_row[3] or {},
            claim_text=origin_row[4],
            geo_dataset=origin_row[5],
            geo_available=origin_row[5] is not None,
        )
        if origin_row
        else None
    )

    indicators = db.execute(
        text("SELECT type, value FROM indicators WHERE case_id = :id ORDER BY type, value"),
        {"id": str(case_id)},
    ).all()
    urls = [v for t, v in indicators if t == "url"]

    groups: dict[str, float] = {}
    for finding in findings:
        groups[finding.signal_group] = round(
            groups.get(finding.signal_group, 0.0) + finding.score_contribution, 2
        )

    return CaseDetail(
        id=case[0],
        case_ref=case[1],
        status=case[2],
        score=case[3],
        band=case[4],
        classification=case[5],
        data_completeness=case[6],
        weights_version=case[7],
        created_at=case[8].isoformat(),
        subject=headers.get("subject"),
        from_address=headers.get("from"),
        reply_to=headers.get("reply-to"),
        return_path=headers.get("return-path"),
        message_id=headers.get("message-id"),
        body_preview=None,
        hops=hops,
        findings=findings,
        auth_results=auth_rows,
        origin=origin,
        group_contributions=groups,
        urls=urls,
        attachments=[],
    )
