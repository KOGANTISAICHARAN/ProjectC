"""Database engines and session factories.

TWO CONNECTIONS, DELIBERATELY
-----------------------------
This module exposes two distinct pools, and keeping them apart is a security
control rather than a tidiness preference:

``SessionLocal`` -- the **system** connection. Privileged, bypasses row-level
security, used by migrations and by the worker. A worker is a system actor that
must process every organisation's jobs, so constraining it to one tenant would
make it useless.

``AppSessionLocal`` -- the **request** connection. Authenticates as an
unprivileged role, so RLS applies. Every read or write made on behalf of a user
goes through it, wrapped in :func:`tenant_scope`.

If a request ever ran on a system session, RLS would not apply and the only
tenancy boundary left would be whether a developer remembered a ``WHERE
org_id``. :func:`tenant_scope` therefore refuses a system session outright, and
``app.db.guards`` refuses to start the API if the request connection turns out
to be privileged.

WHY SYNCHRONOUS
---------------
The heavy work is CPU-bound (MIME parsing, DKIM verification, fingerprinting),
not I/O concurrency, and FastAPI runs sync endpoints in a threadpool. Async also
buys a well-known failure: asyncpg's prepared-statement cache is incompatible
with transaction-mode poolers such as Supabase's Supavisor. Sync SQLAlchemy plus
psycopg3 removes that class of bug entirely.

POOLING
-------
Behind a transaction-mode pooler the server already pools, so layering
SQLAlchemy's own pool on top exhausts the upstream limit as soon as a second
container starts. ``NullPool`` is selected automatically for pooler hosts.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

#: The unprivileged role the RLS policies are written against.
APP_ROLE = "headwaters_app"

#: Marks a session as originating from the app-role factory. Checked by
#: :func:`tenant_scope`; see the module docstring for why this matters.
_APP_SESSION_FLAG = "_headwaters_app_session"


def _behind_pooler(url: str) -> bool:
    """Transaction-mode poolers (Supabase Supavisor) expose port 6543."""
    return "pooler." in url or ":6543/" in url


def _build_engine(url: str, *, application_name: str) -> Engine:
    kwargs: dict[str, object] = {
        "pool_pre_ping": True,
        "echo": False,
        # Fail fast rather than hanging a worker on an unreachable database.
        "connect_args": {"connect_timeout": 10, "application_name": application_name},
    }
    if _behind_pooler(url):
        kwargs["poolclass"] = NullPool
    else:
        kwargs |= {"pool_size": 5, "max_overflow": 5, "pool_recycle": 1800}

    log.info("db.engine.init", application_name=application_name, behind_pooler=_behind_pooler(url))
    return create_engine(url, **kwargs)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """The privileged system engine: migrations, worker, bootstrap.

    Built lazily. Creating it at import time opened a connection pool as a side
    effect of importing this module and emitted a log line before logging was
    configured.
    """
    settings = get_settings()
    return _build_engine(settings.database_url, application_name=f"{settings.service_name}-system")


@lru_cache(maxsize=1)
def get_app_engine() -> Engine:
    """The unprivileged engine used for everything done on behalf of a user."""
    settings = get_settings()
    return _build_engine(
        settings.effective_database_url_app, application_name=f"{settings.service_name}-app"
    )


@lru_cache(maxsize=1)
def _system_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_engine(), autoflush=False, autocommit=False, expire_on_commit=False
    )


@lru_cache(maxsize=1)
def _app_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_app_engine(), autoflush=False, autocommit=False, expire_on_commit=False
    )


def SessionLocal() -> Session:  # noqa: N802 - conventional SQLAlchemy name
    """A privileged system session. Never use this to serve a user request."""
    return _system_factory()()


def AppSessionLocal() -> Session:  # noqa: N802 - matches SessionLocal
    """An unprivileged session on which row-level security applies."""
    session = _app_factory()()
    session.info[_APP_SESSION_FLAG] = True
    return session


def is_app_session(session: Session) -> bool:
    return bool(session.info.get(_APP_SESSION_FLAG, False))


@contextmanager
def tenant_scope(session: Session, user_id: uuid.UUID) -> Iterator[Session]:
    """Bind a session to one analyst so row-level security applies.

    Opens a transaction, drops to the unprivileged role, and sets
    ``app.current_user_id`` -- the GUC every policy reads. Both are ``LOCAL``,
    so they are scoped to this transaction and cannot leak to whatever request
    borrows the same pooled connection next.

    Raises if handed a system session. That mistake is otherwise invisible: the
    query succeeds, returns rows from every organisation, and looks like a
    working feature.
    """
    if not is_app_session(session):
        raise RuntimeError(
            "tenant_scope() was given a privileged system session. "
            "Row-level security would not apply and the query would return every "
            "organisation's rows. Use AppSessionLocal() / the get_tenant_db "
            "dependency for anything acting on behalf of a user."
        )

    with session.begin():
        # set_config() is parameterised; `SET LOCAL <name> = <value>` is not and
        # would mean interpolating a value into SQL.
        session.execute(
            text("SELECT set_config('app.current_user_id', :uid, true)"),
            {"uid": str(user_id)},
        )
        # Defence in depth: if the app engine were ever misconfigured to a role
        # with wider rights, this still drops the transaction to APP_ROLE. The
        # role name is a module constant, never user input.
        session.execute(text(f"SET LOCAL ROLE {APP_ROLE}"))
        yield session


def check_database(engine: Engine | None = None) -> bool:
    """Readiness probe. Returns False rather than raising: an unready service
    should report unready, not 500."""
    target = engine if engine is not None else get_engine()
    try:
        with target.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    # A readiness probe must never propagate.
    except Exception as exc:
        log.warning("db.healthcheck.failed", error=str(exc))
        return False
