"""The Postgres-backed work queue.

Concurrency correctness is the whole point of this table, so these tests use
real sessions against real Postgres. ``SKIP LOCKED`` cannot be verified against
a mock.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from app.models.enums import JobKind, JobState
from app.services import jobs
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from tests.conftest import requires_db

pytestmark = requires_db


def _enqueue(db: Session, org_id: uuid.UUID, case_id: uuid.UUID, kind: JobKind) -> uuid.UUID | None:
    job_id = jobs.enqueue(db, org_id=org_id, kind=kind, case_id=case_id, payload={"k": 1})
    db.commit()
    return job_id


def _extra_case(db: Session, org_id: uuid.UUID) -> uuid.UUID:
    """Create a minimal case row. jobs.case_id is a foreign key, so a synthetic
    UUID would violate it."""
    case_id = db.execute(
        text(
            "INSERT INTO cases (org_id, case_ref, status) "
            "VALUES (:o, :ref, 'complete') RETURNING id"
        ),
        {"o": str(org_id), "ref": f"CASE-T-{uuid.uuid4().hex[:8]}"},
    ).scalar_one()
    db.commit()
    return case_id


def test_duplicate_enqueue_for_the_same_case_and_kind_is_deduplicated(
    db: Session, two_orgs: dict
) -> None:
    """`uq_jobs_active_kind_per_case` makes enqueue idempotent while a job is
    still active.

    Without it, a user double-clicking "generate report", or a retrying client,
    produces duplicate work and duplicate evidence events for one action.
    """
    first = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    second = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)

    assert first is not None
    assert second is None, "a second active job was created for the same case and kind"

    # Once the first completes, the same kind may be enqueued again: the guard
    # covers concurrent duplicates, not a legitimate re-run.
    claimed = jobs.claim(db, worker_id="w")
    assert claimed is not None
    jobs.complete(db, claimed.id)
    db.commit()

    third = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    assert third is not None


def test_enqueue_and_claim_round_trip(db: Session, two_orgs: dict) -> None:
    job_id = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    assert job_id is not None

    claimed = jobs.claim(db, worker_id="w1")
    assert claimed is not None
    assert claimed.id == job_id
    assert claimed.kind is JobKind.GENERATE_REPORT
    assert claimed.attempts == 1
    assert claimed.payload == {"k": 1}

    jobs.complete(db, claimed.id)
    state = db.execute(text("SELECT state FROM jobs WHERE id=:i"), {"i": job_id}).scalar()
    assert state == JobState.DONE.value


def test_duplicate_kind_per_case_is_rejected(db: Session, two_orgs: dict) -> None:
    """A double-clicked upload must not enqueue the same OpenAI call twice.

    The partial unique index covers queued-and-running only, so the same kind
    may legitimately be re-run after the first completes.
    """
    first = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    second = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    assert first is not None
    assert second is None, "duplicate pending job of the same kind was accepted"

    claimed = jobs.claim(db, worker_id="w1")
    assert claimed is not None
    jobs.complete(db, claimed.id)

    third = _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    assert third is not None, "re-running a kind after completion must be allowed"


def test_two_workers_never_claim_the_same_job(db: Session, engine: Engine, two_orgs: dict) -> None:
    """The property SKIP LOCKED exists to provide.

    Two independent sessions claim concurrently; each job must go to exactly one
    worker, and neither worker may block on the other.
    """
    # One job per case, because `uq_jobs_active_kind_per_case` permits only one
    # ACTIVE job per (case, kind) -- enqueuing the same kind three times for one
    # case would produce a single job and prove nothing about concurrency.
    case_ids = [_extra_case(db, two_orgs["org_a"]) for _ in range(3)]
    for case_id in case_ids:
        _enqueue(db, two_orgs["org_a"], case_id, JobKind.GENERATE_REPORT)
    kinds = case_ids  # loop bound below

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s1, s2 = factory(), factory()
    try:
        claimed: list[uuid.UUID] = []
        for _ in range(len(kinds)):
            a = jobs.claim(s1, worker_id="w1")
            b = jobs.claim(s2, worker_id="w2")
            claimed += [j.id for j in (a, b) if j is not None]

        assert len(claimed) == len(kinds), "a job was lost or over-delivered"
        assert len(set(claimed)) == len(claimed), "the same job was claimed twice"
    finally:
        s1.close()
        s2.close()


def test_failure_schedules_a_backoff_retry(db: Session, two_orgs: dict) -> None:
    _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    job = jobs.claim(db, worker_id="w1")
    assert job is not None

    jobs.fail(db, job, "provider timeout")

    row = db.execute(
        text("SELECT state, attempts, last_error, run_after > now() FROM jobs WHERE id=:i"),
        {"i": job.id},
    ).first()
    assert row is not None
    assert row[0] == JobState.QUEUED.value
    assert row[1] == 1
    assert "provider timeout" in row[2]
    assert row[3] is True, "retry must be deferred, not immediately re-claimable"


def test_exhausted_attempts_bury_the_job(db: Session, two_orgs: dict) -> None:
    """A poison job must stop, not spin forever burning provider quota."""
    jobs.enqueue(
        db,
        org_id=two_orgs["org_a"],
        kind=JobKind.GENERATE_REPORT,
        case_id=two_orgs["case_a"],
        max_attempts=1,
    )
    db.commit()

    job = jobs.claim(db, worker_id="w1")
    assert job is not None
    jobs.fail(db, job, "permanent schema refusal")

    state = db.execute(text("SELECT state FROM jobs WHERE id=:i"), {"i": job.id}).scalar()
    assert state == JobState.DEAD.value


def test_stale_leases_are_reclaimed(db: Session, two_orgs: dict) -> None:
    """A killed worker must not strand its job forever."""
    _enqueue(db, two_orgs["org_a"], two_orgs["case_a"], JobKind.GENERATE_REPORT)
    job = jobs.claim(db, worker_id="crashed-worker")
    assert job is not None

    db.execute(
        text("UPDATE jobs SET locked_at = now() - interval '1 hour' WHERE id=:i"), {"i": job.id}
    )
    db.commit()

    assert jobs.reclaim_stale(db, older_than=timedelta(minutes=15)) == 1
    state = db.execute(text("SELECT state FROM jobs WHERE id=:i"), {"i": job.id}).scalar()
    assert state == JobState.QUEUED.value


def test_empty_queue_returns_none(db: Session) -> None:
    db.execute(text("DELETE FROM jobs"))
    db.commit()
    assert jobs.claim(db, worker_id="w1") is None


def test_queue_depth_reports_every_state(db: Session) -> None:
    depth = jobs.queue_depth(db)
    assert set(depth) == {s.value for s in JobState}
