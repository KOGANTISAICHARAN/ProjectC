"""Test fixtures.

The environment is set **explicitly**, not with ``setdefault``: ambient shell
variables must never change a test outcome. A developer with ``ALLOWED_ORIGINS``
exported in their shell must get the same result as CI.

Database-backed tests need a real Postgres -- row-level security, ``SKIP
LOCKED`` and partial indexes are Postgres behaviours, and a SQLite stand-in
would prove nothing about any of them. They are skipped rather than failed when
no database is reachable, so ``pytest`` stays useful outside the compose stack.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

# --------------------------------------------------------------- environment
ALLOWED_ORIGIN = "http://localhost:3100"
UNLISTED_ORIGIN = "https://evil.example"

_TEST_ENV = {
    "DATABASE_URL": os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg://headwaters:headwaters@localhost:5432/headwaters",
    ),
    "ENVIRONMENT": "local",
    "ALLOWED_ORIGINS": f"{ALLOWED_ORIGIN},http://example.test",
    "LOG_LEVEL": "WARNING",
    # Explicitly blank: exercises the "blank means unset" coercion.
    "OPENAI_API_KEY": "",
    "SENTRY_DSN": "",
}
for _key, _value in _TEST_ENV.items():
    os.environ[_key] = _value

DB_URL = os.environ.get("TEST_DATABASE_URL", _TEST_ENV["DATABASE_URL"])


# --------------------------------------------------------------------- app
@pytest.fixture(scope="session")
def client() -> Iterator[TestClient]:
    from app.core.config import get_settings

    get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


# ---------------------------------------------------------------- database
def _reachable(url: str) -> bool:
    if not url:
        return False
    try:
        eng = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 3})
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        eng.dispose()
        return True
    except Exception:
        return False


requires_db = pytest.mark.skipif(
    not _reachable(DB_URL), reason="no reachable Postgres (set TEST_DATABASE_URL)"
)


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    eng = create_engine(DB_URL, pool_pre_ping=True)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    """A privileged session, as the migration owner.

    Used for setup and teardown only. Tests asserting on tenancy must drop to
    the unprivileged role via ``as_user`` -- the owner bypasses RLS, so an
    assertion made on this session would pass with no policies at all.
    """
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def two_orgs(db: Session) -> Iterator[dict[str, uuid.UUID]]:
    """Two organisations, one analyst each, one case each.

    The canonical tenancy fixture: if analyst A can reach org B's case, private
    correspondence has leaked.
    """
    ids = {
        "org_a": uuid.uuid4(),
        "org_b": uuid.uuid4(),
        "user_a": uuid.uuid4(),
        "user_b": uuid.uuid4(),
        "case_a": uuid.uuid4(),
        "case_b": uuid.uuid4(),
    }
    for side in ("a", "b"):
        db.execute(
            text("INSERT INTO orgs (id, name, slug) VALUES (:id, :n, :s)"),
            {
                "id": ids[f"org_{side}"],
                "n": f"Org {side.upper()}",
                "s": f"org-{side}-{ids[f'org_{side}'].hex[:8]}",
            },
        )
        db.execute(
            text("INSERT INTO users (id, email) VALUES (:id, :e)"),
            {"id": ids[f"user_{side}"], "e": f"{ids[f'user_{side}'].hex[:12]}@example.test"},
        )
        db.execute(
            text("INSERT INTO memberships (org_id, user_id, role) VALUES (:o, :u, 'analyst')"),
            {"o": ids[f"org_{side}"], "u": ids[f"user_{side}"]},
        )
        db.execute(
            text(
                "INSERT INTO cases (id, org_id, case_ref, status) "
                "VALUES (:id, :o, :ref, 'received')"
            ),
            {
                "id": ids[f"case_{side}"],
                "o": ids[f"org_{side}"],
                "ref": f"CASE-{side.upper()}-{ids[f'case_{side}'].hex[:6]}",
            },
        )
    db.commit()

    yield ids

    db.rollback()
    for key in ("org_a", "org_b"):
        db.execute(text("DELETE FROM orgs WHERE id = :id"), {"id": ids[key]})
    for key in ("user_a", "user_b"):
        db.execute(text("DELETE FROM users WHERE id = :id"), {"id": ids[key]})
    db.commit()
