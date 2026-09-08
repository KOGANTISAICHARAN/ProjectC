"""Job handlers.

Registered against :data:`app.workers.runner.HANDLERS`. Only kinds that have a
real implementation are registered: an unregistered kind is buried immediately
with an explicit reason rather than retried forever, so the queue never fills
with work nobody wrote.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.enums import EvidenceAction, JobKind
from app.services import jobs
from app.services.evidence.chain import append_event
from app.services.reporting.builder import build_report, persist_report

log = get_logger(__name__)


def generate_report(db: Session, job: jobs.ClaimedJob) -> None:
    """Render and record a forensic report.

    Genuinely asynchronous work: rendering is CPU-bound and a caller should not
    hold an HTTP connection open for it.
    """
    if job.case_id is None:
        raise ValueError("generate_report requires a case_id")

    html, digest = build_report(db, job.case_id)
    meta = persist_report(db, org_id=job.org_id, case_id=job.case_id, html=html, digest=digest)
    append_event(
        db,
        org_id=job.org_id,
        case_id=job.case_id,
        actor="worker:reporting",
        action=EvidenceAction.REPORT_GENERATED,
        payload={"report_sha256": digest, "version": meta["version"]},
        metadata={"format": "html", "generated_by": "worker"},
    )
    db.commit()
    log.info("worker.report_generated", case_id=str(job.case_id), version=meta["version"])


def register(handlers: dict[JobKind, object]) -> None:
    handlers[JobKind.GENERATE_REPORT] = generate_report
