"""Forensic report.

Rendered as self-contained HTML rather than PDF. WeasyPrint pulls a large native
stack (Pango, Cairo, HarfBuzz) into the image for one feature; a single HTML file
prints to PDF from any browser, is diffable, needs no fonts installed, and can be
attached to a ticket as-is. The document is print-styled so Ctrl-P produces the
same pagination everywhere.

Every figure in the report is read back from the database rather than recomputed,
so the report states what was *recorded*, not what the code would produce today.
That distinction is the difference between a report and a re-run.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.services.evidence.chain import verify_chain

log = get_logger(__name__)

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(_TEMPLATES),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_pdf(html: str) -> bytes | None:
    """Render the report HTML to PDF.

    Returns None when WeasyPrint is unavailable, so the caller can fall back to
    serving HTML and *say so* rather than serving a file named .pdf that is not
    one. WeasyPrint binds to system pango/cairo at import time, so a successful
    pip install does not guarantee a working renderer -- the failure has to be
    handled at run time, not assumed away at build time.
    """
    try:
        from weasyprint import HTML

        return bytes(HTML(string=html).write_pdf())
    except Exception as exc:
        log.warning("report.pdf_unavailable", error=f"{type(exc).__name__}: {str(exc)[:160]}")
        return None


def build_report(db: Session, case_id: uuid.UUID) -> tuple[str, str]:
    """Render the report. Returns (html, sha256_of_html)."""
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
        raise ValueError("case not found")

    artifact = db.execute(
        text(
            "SELECT sha256, size_bytes, filename, acquired_at, source, parse_status "
            "FROM email_artifacts WHERE case_id = :id"
        ),
        {"id": str(case_id)},
    ).first()

    headers = {
        name.lower(): value
        for name, value in db.execute(
            text("SELECT name, value_raw FROM email_headers WHERE case_id = :id ORDER BY ordinal"),
            {"id": str(case_id)},
        ).all()
    }

    hops = db.execute(
        text(
            "SELECT seq, helo, observed_ip, by_host, ip_class, role, trust_state, "
            "hop_ts_utc, anomalies FROM received_hops WHERE case_id = :id ORDER BY seq"
        ),
        {"id": str(case_id)},
    ).all()

    origin = db.execute(
        text(
            "SELECT feos_ip, boundary_hop_seq, confidence, confidence_breakdown, "
            "claim_text, geo_dataset FROM origin_assessment WHERE case_id = :id"
        ),
        {"id": str(case_id)},
    ).first()

    auth = db.execute(
        text(
            "SELECT mechanism, result_reported, authserv_id, aligned, d_domain, caveat "
            "FROM auth_results WHERE case_id = :id ORDER BY mechanism"
        ),
        {"id": str(case_id)},
    ).all()

    findings = db.execute(
        text(
            "SELECT signal_group, rule_id, severity, title, detail, score_contribution, "
            "evidence_ref, evidence_quote, mitre_technique FROM findings "
            "WHERE case_id = :id ORDER BY score_contribution DESC"
        ),
        {"id": str(case_id)},
    ).all()

    indicators = db.execute(
        text("SELECT type, value FROM indicators WHERE case_id = :id ORDER BY type, value"),
        {"id": str(case_id)},
    ).all()

    campaign = db.execute(
        text(
            """
            SELECT c.name, c.member_count, c.summary, m.dna_score, m.locus_breakdown
              FROM campaigns c JOIN campaign_members m ON m.campaign_id = c.id
             WHERE m.case_id = :id
            """
        ),
        {"id": str(case_id)},
    ).first()

    verification = verify_chain(db, case_id)
    events = db.execute(
        text(
            "SELECT seq, ts_utc, actor, action, payload_hash, entry_hash "
            "FROM evidence_events WHERE case_id = :id ORDER BY seq"
        ),
        {"id": str(case_id)},
    ).all()

    mitre = sorted({f[8] for f in findings if f[8]})

    html = _env.get_template("report.html").render(
        generated_at=datetime.now(UTC),
        case={
            "id": case[0],
            "ref": case[1],
            "status": case[2],
            "score": case[3],
            "band": case[4],
            "classification": case[5],
            "completeness": case[6],
            "weights_version": case[7],
            "created_at": case[8],
        },
        artifact=artifact,
        headers=headers,
        hops=hops,
        origin=origin,
        auth=auth,
        findings=findings,
        indicators=indicators,
        campaign=campaign,
        verification=verification,
        events=events,
        mitre=mitre,
    )
    return html, hashlib.sha256(html.encode("utf-8")).hexdigest()


def persist_report(
    db: Session, *, org_id: uuid.UUID, case_id: uuid.UUID, html: str, digest: str
) -> dict[str, Any]:
    version = (
        db.execute(
            text("SELECT coalesce(max(version), 0) FROM reports WHERE case_id = :c"),
            {"c": str(case_id)},
        ).scalar_one()
        + 1
    )
    report_id = db.execute(
        text(
            """
            INSERT INTO reports (org_id, case_id, version, pdf_sha256, size_bytes,
                                 state, includes_s63_cert, merkle_root)
            VALUES (:o, :c, :v, :sha, :size, 'ready', true, :root)
            RETURNING id
            """
        ),
        {
            "o": str(org_id),
            "c": str(case_id),
            "v": version,
            "sha": digest,
            "size": len(html.encode()),
            "root": verify_chain(db, case_id).merkle_root,
        },
    ).scalar_one()
    log.info("report.generated", case_id=str(case_id), version=version, sha256=digest)
    return {"report_id": report_id, "version": version, "sha256": digest}
