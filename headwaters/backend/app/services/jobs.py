"""The Band B work queue.

Postgres is the broker. ``SELECT ... FOR UPDATE SKIP LOCKED`` gives exactly-once
delivery under concurrent workers without a second service to operate, and --
more importantly here -- lets a case row and its first job be created in one
transaction. A case that exists without its enrichment job, or a job whose case
was rolled back, are both states this design makes unrepresentable.

Workers act as system actors across every organisation, so this module does NOT
use ``tenant_scope``: the connection it runs on is expected to bypass RLS. That
is a deliberate, load-bearing asymmetry -- user-facing reads are constrained by
policy, background processing is not, and the two must not share a session.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.enums import JobKind, JobState

log = get_logger(__name__)

#: A job leased for longer than this is presumed abandoned (worker crashed, pod
#: evicted) and is returned to the queue by :func:`reclaim_stale`.
STALE_LEASE = timedelta(minutes=15)

#: Backoff is exponential with a ceiling, so a provider outage does not turn
#: into a retry storm and a poison job does not spin.
BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    """A leased unit of work. Frozen: a worker must not mutate its own lease."""

    id: uuid.UUID
    org_id: uuid.UUID
    case_id: uuid.UUID | None
    kind: JobKind
    attempts: int
    max_attempts: int
    payload: dict[str, Any]


def enqueue(
    db: Session,
    *,
    org_id: uuid.UUID,
    kind: JobKind,
    case_id: uuid.UUID | None = None,
    payload: dict[str, Any] | None = None,
    max_attempts: int = 3,
    delay_seconds: int = 0,
) -> uuid.UUID | None:
    """Add a job. Returns None if an identical one is already pending.

    A partial unique index permits only one queued-or-running job of a given
    kind per case, so a double-clicked upload or a retried webhook cannot
    enqueue the same OpenAI call twice. The conflict is swallowed here because
    "it is already scheduled" is success from the caller's point of view.

    Does NOT commit: the caller owns the transaction, which is the entire point
    of putting the queue in the database.
    """
    row = db.execute(
        text(
            """
            INSERT INTO jobs (org_id, case_id, kind, state, payload, max_attempts, run_after)
            VALUES (:org_id, :case_id, :kind, 'queued', CAST(:payload AS jsonb),
                    :max_attempts, now() + make_interval(secs => :delay))
            ON CONFLICT DO NOTHING
            RETURNING id
            """
        ),
        {
            "org_id": str(org_id),
            "case_id": str(case_id) if case_id else None,
            "kind": kind.value,
            "payload": _json(payload or {}),
            "max_attempts": max_attempts,
            "delay": delay_seconds,
        },
    ).first()

    if row is None:
        log.info("job.enqueue.duplicate", kind=kind.value, case_id=str(case_id))
        return None
    job_id: uuid.UUID = row[0]
    log.info("job.enqueued", job_id=str(job_id), kind=kind.value, case_id=str(case_id))
    return job_id


def claim(
    db: Session, *, worker_id: str, kinds: tuple[JobKind, ...] | None = None
) -> ClaimedJob | None:
    """Lease one job, or return None if the queue is empty.

    The inner SELECT takes a row lock and skips rows other workers hold, so N
    workers make progress without coordinating. Ordering by ``run_after`` then
    ``created_at`` makes the queue fair and makes backoff meaningful.

    Commits immediately: the lease must be visible to other workers even though
    the work itself has not started. A lease held inside the work transaction
    would be released by a crash *and* by a rollback, allowing two workers to
    process the same job.
    """
    kind_filter = ""
    params: dict[str, Any] = {"worker_id": worker_id}
    if kinds:
        kind_filter = "AND kind = ANY(:kinds)"
        params["kinds"] = [k.value for k in kinds]

    row = db.execute(
        text(
            f"""
            UPDATE jobs
               SET state      = 'running',
                   attempts   = attempts + 1,
                   locked_at  = now(),
                   locked_by  = :worker_id
             WHERE id = (
                 SELECT id FROM jobs
                  WHERE state = 'queued'
                    AND run_after <= now()
                    {kind_filter}
                  ORDER BY run_after, created_at
                  FOR UPDATE SKIP LOCKED
                  LIMIT 1
             )
         RETURNING id, org_id, case_id, kind, attempts, max_attempts, payload
            """  # noqa: S608 - kind_filter is a literal, params are bound
        ),
        params,
    ).first()
    db.commit()

    if row is None:
        return None

    job = ClaimedJob(
        id=row[0],
        org_id=row[1],
        case_id=row[2],
        kind=JobKind(row[3]),
        attempts=row[4],
        max_attempts=row[5],
        payload=row[6] or {},
    )
    log.info("job.claimed", job_id=str(job.id), kind=job.kind.value, attempt=job.attempts)
    return job


def complete(db: Session, job_id: uuid.UUID) -> None:
    db.execute(
        text(
            "UPDATE jobs SET state='done', finished_at=now(), locked_by=NULL, "
            "last_error=NULL WHERE id=:id"
        ),
        {"id": str(job_id)},
    )
    db.commit()
    log.info("job.completed", job_id=str(job_id))


def fail(db: Session, job: ClaimedJob, error: str, *, force_dead: bool = False) -> None:
    """Record a failure and either schedule a retry or bury the job.

    ``force_dead`` buries it immediately, for failures no retry can fix -- an
    unregistered job kind, a permanently malformed payload. Retrying those is
    just a slow way to fill the error column and burn provider quota.

    ``error`` is truncated: it can contain a provider response, and an unbounded
    error column is how a queue table becomes the largest object in the database.
    """
    exhausted = force_dead or job.attempts >= job.max_attempts
    backoff = min(BACKOFF_BASE_SECONDS * (2 ** (job.attempts - 1)), BACKOFF_MAX_SECONDS)

    db.execute(
        text(
            """
            UPDATE jobs
               SET state      = CASE WHEN :exhausted THEN 'dead' ELSE 'queued' END,
                   run_after  = now() + make_interval(secs => :backoff),
                   locked_by  = NULL,
                   locked_at  = NULL,
                   last_error = :error,
                   finished_at = CASE WHEN :exhausted THEN now() ELSE NULL END
             WHERE id = :id
            """
        ),
        {
            "id": str(job.id),
            "exhausted": exhausted,
            "backoff": 0 if exhausted else backoff,
            "error": error[:2000],
        },
    )
    db.commit()
    log.warning(
        "job.failed",
        job_id=str(job.id),
        kind=job.kind.value,
        attempt=job.attempts,
        exhausted=exhausted,
        retry_in_s=None if exhausted else backoff,
    )


def reclaim_stale(db: Session, older_than: timedelta = STALE_LEASE) -> int:
    """Return abandoned leases to the queue.

    A worker that is killed mid-job leaves its row in ``running`` forever. Any
    queue without this sweep silently loses work the first time a container is
    evicted.
    """
    cutoff = datetime.now(UTC) - older_than
    # RETURNING rather than rowcount: Session.execute() is typed as Result, and
    # only CursorResult carries rowcount. Counting the returned ids is both
    # type-safe and portable.
    reclaimed = db.execute(
        text(
            """
            UPDATE jobs
               SET state='queued', locked_by=NULL, locked_at=NULL,
                   last_error='lease expired; reclaimed'
             WHERE state='running' AND locked_at < :cutoff
         RETURNING id
            """
        ),
        {"cutoff": cutoff},
    ).all()
    db.commit()
    count = len(reclaimed)
    if count:
        log.warning("job.leases_reclaimed", count=count)
    return count


def queue_depth(db: Session) -> dict[str, int]:
    """Per-state counts. Exported as a metric: a rising queued count is the
    earliest signal that Band B is falling behind."""
    rows = db.execute(text("SELECT state, count(*) FROM jobs GROUP BY state")).all()
    depth = {s.value: 0 for s in JobState}
    depth.update({r[0]: r[1] for r in rows})
    return depth


def _json(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), sort_keys=True)
