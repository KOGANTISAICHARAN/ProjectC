"""Report generation and download."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.enums import EvidenceAction
from app.security.deps import get_tenant_db
from app.security.identity import DEMO_ORG_ID, resolve_user_id
from app.services.evidence.chain import append_event
from app.services.reporting.builder import build_report, persist_report, render_pdf

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["reports"])


def tenant_session(user_id: Annotated[uuid.UUID, Depends(resolve_user_id)]) -> Any:
    yield from get_tenant_db(user_id)


TenantDb = Annotated[Session, Depends(tenant_session)]
UserId = Annotated[uuid.UUID, Depends(resolve_user_id)]


@router.post("/cases/{case_id}/reports", status_code=status.HTTP_201_CREATED)
def create_report(case_id: uuid.UUID, db: TenantDb, user_id: UserId) -> dict[str, Any]:
    """Generate a report and record its generation in the chain of custody.

    Producing a report is itself an evidentiary act: it fixes a set of findings
    at a moment in time, so it is recorded like any other.
    """
    try:
        html, digest = build_report(db, case_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc

    meta = persist_report(db, org_id=DEMO_ORG_ID, case_id=case_id, html=html, digest=digest)

    append_event(
        db,
        org_id=DEMO_ORG_ID,
        case_id=case_id,
        actor=str(user_id),
        action=EvidenceAction.REPORT_GENERATED,
        payload={"report_sha256": digest, "version": meta["version"]},
        metadata={
            "format": "pdf" if render_pdf(html) is not None else "html-fallback",
            "includes_s63_certificate": True,
        },
    )
    db.flush()
    return {
        **meta,
        "report_id": str(meta["report_id"]),
        "download": f"/api/v1/reports/{meta['report_id']}",
    }


@router.get("/reports/{report_id}", response_class=Response)
def download_report(report_id: uuid.UUID, db: TenantDb) -> Response:
    """Re-render the report for a recorded case.

    Rendered on demand rather than served from a stored blob: object storage
    lands in a later phase, and returning a file we did not store would be a
    fiction. The recorded ``pdf_sha256`` still pins what was generated, and a
    mismatch is reported rather than hidden.
    """
    row = db.execute(
        text("SELECT case_id, pdf_sha256, version FROM reports WHERE id = :id"),
        {"id": str(report_id)},
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    html, digest = build_report(db, row[0])
    if digest != row[1]:
        # Honest rather than silent: the case changed after the report was
        # recorded, so this rendering is not byte-identical to the one whose
        # hash was filed.
        html = html.replace(
            "<body>",
            "<body><div style='background:#fbf4e6;border-left:3px solid #8a6210;"
            "padding:8pt 10pt;margin-bottom:10pt;font-size:9pt'>"
            "<b>Note:</b> this rendering differs from the report recorded as version "
            f"{row[2]} (recorded hash <code>{row[1][:16]}…</code>, this rendering "
            f"<code>{digest[:16]}…</code>). The case record changed after that report "
            "was generated.</div>",
            1,
        )

    # PDF is the deliverable; HTML is the fallback, and the response says which
    # one it is. Serving HTML under a .pdf filename would be a small lie that a
    # forensic tool cannot afford.
    pdf = render_pdf(html)
    if pdf is not None:
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'inline; filename="headwaters-{report_id}.pdf"',
                "X-Report-Format": "pdf",
                "X-Report-SHA256": digest,
            },
        )

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'inline; filename="headwaters-{report_id}.html"',
            "X-Report-Format": "html-fallback",
            "X-Report-SHA256": digest,
        },
    )
