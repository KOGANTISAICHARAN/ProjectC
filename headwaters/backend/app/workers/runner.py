"""Worker entrypoint.

Shares this image and codebase with the API so ``services/`` can never drift
between the process that accepts an upload and the process that enriches it.

The loop is deliberately simple: claim one job, dispatch it, record the outcome,
repeat. Handlers are registered per :class:`JobKind` and arrive with their
phases -- a kind with no handler is logged and buried rather than retried
forever, because retrying work nobody implemented is just a slow way to fill the
error column.
"""

from __future__ import annotations

import os
import signal
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import FrameType

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.guards import assert_privileged
from app.db.session import (
    SessionLocal,
    check_database,
    get_engine,
)
from app.models.enums import JobKind
from app.services import jobs

log = get_logger(__name__)

#: Seconds to sleep when the queue is empty. Long enough that an idle worker is
#: not a busy-loop against the database, short enough that a demo does not
#: visibly stall waiting for enrichment.
IDLE_SLEEP = 2.0

#: How often to sweep for leases abandoned by crashed workers.
RECLAIM_EVERY = 60.0

#: Liveness signal. The worker exposes no HTTP port, so an HTTP probe is
#: meaningless -- and inheriting the API's would fail forever and put the
#: container in a restart loop. Touching a file each iteration proves the thing
#: that actually matters: the *loop* is turning. A process that is alive but
#: wedged on a database call still fails this check, which an "is the process
#: running" probe would not catch.
HEARTBEAT_PATH = Path(os.environ.get("WORKER_HEARTBEAT", "/tmp/headwaters-worker.heartbeat"))  # noqa: S108

#: Populated as each phase lands. Signature: (Session, ClaimedJob) -> None.
HANDLERS: dict[JobKind, Callable[[Session, jobs.ClaimedJob], None]] = {}


class _Shutdown:
    """Cooperative shutdown.

    SIGTERM must not abandon a job mid-flight: the container gets a grace period,
    so we finish the current unit of work and stop before claiming another.
    Killing between jobs turns a deploy into a no-op instead of a lease that has
    to time out fifteen minutes later.
    """

    def __init__(self) -> None:
        self.requested = False
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(signal.SIGINT, self._handle)

    def _handle(self, signum: int, _frame: FrameType | None) -> None:
        log.info("worker.shutdown_requested", signal=signum)
        self.requested = True


#: How long to wait for migrations to land before giving up. Generous: a slow
#: first migration on a cold database is normal, and exiting early just makes
#: the orchestrator restart into the same race.
SCHEMA_WAIT_SECONDS = 120.0
SCHEMA_POLL_SECONDS = 2.0


def _await(predicate: Callable[[], bool], description: str) -> bool:
    """Poll ``predicate`` until true or the deadline passes."""
    deadline = time.monotonic() + SCHEMA_WAIT_SECONDS
    announced = False
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception as exc:
            log.debug("worker.await_check_failed", check=description, error=str(exc)[:120])
        if not announced:
            log.info("worker.awaiting", waiting_for=description)
            announced = True
        time.sleep(SCHEMA_POLL_SECONDS)
    return False


def _await_schema() -> bool:
    """Block until the tables this worker needs exist."""
    from sqlalchemy import text

    from app.db.session import get_engine

    deadline = time.monotonic() + SCHEMA_WAIT_SECONDS
    announced = False

    while time.monotonic() < deadline:
        try:
            with get_engine().connect() as conn:
                present = conn.execute(
                    text("SELECT to_regclass('public.jobs') IS NOT NULL")
                ).scalar_one()
            if present:
                return True
        except Exception as exc:
            log.debug("worker.schema_check_failed", error=str(exc)[:120])

        if not announced:
            log.info(
                "worker.awaiting_schema",
                note="migrations are applied by the API's pre-deploy step; waiting",
            )
            announced = True
        time.sleep(SCHEMA_POLL_SECONDS)

    return False


def _worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def run_forever() -> int:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=settings.environment != "local")
    worker_id = _worker_id()
    log.info("worker.startup", worker_id=worker_id, environment=settings.environment)

    # Wait for connectivity rather than exiting on the first failure.
    #
    # A container start can race DNS for the database host -- particularly right
    # after a network is recreated -- and exiting turns a two-second blip into a
    # crash loop that reads like a broken service. The restart policy did make it
    # converge, but a worker that waits is honest about what it is doing; one
    # that exits repeatedly looks like a fault in every dashboard.
    if not _await(check_database, "database unreachable"):
        log.error("worker.startup.failed", reason="database unreachable")
        return 1

    # Wait for the schema before entering the loop.
    #
    # Migrations are run by the API's pre-deploy step, and nothing orders the
    # worker after it -- not compose, and not Render, which starts services
    # independently. Without this wait a cold start is a race the worker loses:
    # it connects to a healthy but empty database and dies on a missing table.
    if not _await_schema():
        log.error("worker.startup.failed", reason="schema not present within timeout")
        return 1

    # The worker runs on the SYSTEM connection and is expected to bypass RLS: it
    # is a system actor that must drain every organisation's jobs. Logged
    # explicitly so the asymmetry with the request path is visible in operations
    # rather than buried in a docstring.
    privileges = assert_privileged(get_engine(), label="worker")
    log.info(
        "worker.privileges",
        role=privileges.role,
        bypasses_rls=privileges.bypasses_rls,
        note="intended: a worker spans all organisations",
    )

    from app.workers import handlers as handler_module

    handler_module.register(HANDLERS)  # type: ignore[arg-type]

    shutdown = _Shutdown()
    last_reclaim = 0.0
    log.info("worker.ready", worker_id=worker_id, handlers=sorted(k.value for k in HANDLERS))

    while not shutdown.requested:
        _heartbeat()
        now = time.monotonic()
        if now - last_reclaim > RECLAIM_EVERY:
            with SessionLocal() as db:
                jobs.reclaim_stale(db)
            last_reclaim = now

        with SessionLocal() as db:
            job = jobs.claim(db, worker_id=worker_id)
            if job is None:
                time.sleep(IDLE_SLEEP)
                continue
            try:
                _dispatch(db, job)
            except Exception:
                # Belt and braces. _dispatch already contains the handler in a
                # try/except; this guards the bookkeeping around it. A single
                # bad job must never take the worker down and stall every other
                # organisation's enrichment -- which is exactly what an
                # unguarded dispatch did the first time this ran.
                log.exception("worker.dispatch_failed", job_id=str(job.id))
                db.rollback()

    log.info("worker.stopped", worker_id=worker_id)
    return 0


def _heartbeat() -> None:
    """Record that the loop is turning. Never fatal: an unwritable temp
    directory must degrade the health signal, not stop the worker."""
    try:
        HEARTBEAT_PATH.touch()
    except OSError as exc:
        log.warning("worker.heartbeat_failed", error=str(exc))


def _dispatch(db: Session, job: jobs.ClaimedJob) -> None:
    handler = HANDLERS.get(job.kind)
    if handler is None:
        # Not an error worth retrying: no amount of waiting will produce a
        # handler. Bury it immediately with an explicit reason.
        jobs.fail(
            db,
            job,
            f"no handler registered for kind '{job.kind.value}'",
            force_dead=True,
        )
        return

    started = time.perf_counter()
    try:
        handler(db, job)
    # The loop must survive any handler: one bad job must not take the worker
    # down and stall every other organisation's enrichment.
    except Exception as exc:
        db.rollback()
        log.exception("worker.handler_failed", job_id=str(job.id), kind=job.kind.value)
        jobs.fail(db, job, f"{type(exc).__name__}: {exc}")
        return

    jobs.complete(db, job.id)
    log.info(
        "worker.handled",
        job_id=str(job.id),
        kind=job.kind.value,
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
    )


if __name__ == "__main__":
    sys.exit(run_forever())
