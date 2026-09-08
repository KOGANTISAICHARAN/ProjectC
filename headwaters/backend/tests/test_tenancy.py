"""Row-level security.

The premise of every test here: the application layer is *deliberately removed*.
No ``WHERE org_id = ...`` appears in a single query below. If a row from another
organisation comes back, the database is not protecting us -- and a forgotten
filter in one handler would then be a disclosure of somebody's private mail.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from tests.conftest import requires_db

pytestmark = requires_db


@contextmanager
def as_user(db: Session, user_id: uuid.UUID) -> Iterator[Session]:
    """Run statements as the unprivileged application role, bound to a user.

    ``SET LOCAL ROLE`` is essential. The migration owner -- and any superuser --
    bypasses row-level security even when the table is FORCE-enabled, so a test
    that skipped this would pass regardless of whether any policy existed.
    """
    db.rollback()
    db.begin()
    db.execute(text("SELECT set_config('app.current_user_id', :u, true)"), {"u": str(user_id)})
    db.execute(text("SET LOCAL ROLE headwaters_app"))
    try:
        yield db
    finally:
        db.rollback()


def test_analyst_sees_only_their_own_org_cases(db: Session, two_orgs: dict) -> None:
    with as_user(db, two_orgs["user_a"]) as s:
        # No org filter. Any leakage is the database's failure, which is exactly
        # what this layer exists to prevent.
        visible = {r[0] for r in s.execute(text("SELECT id FROM cases")).all()}

    assert two_orgs["case_a"] in visible
    assert two_orgs["case_b"] not in visible, "org B's case leaked to an org A analyst"


def test_direct_lookup_of_another_orgs_case_returns_nothing(db: Session, two_orgs: dict) -> None:
    """Knowing a case id must not be enough to read it."""
    with as_user(db, two_orgs["user_a"]) as s:
        row = s.execute(
            text("SELECT id FROM cases WHERE id = :id"), {"id": two_orgs["case_b"]}
        ).first()
    assert row is None


def test_analyst_cannot_write_into_another_org(db: Session, two_orgs: dict) -> None:
    """WITH CHECK blocks writes, not only reads.

    A read-only policy would still let an attacker plant evidence in another
    tenant's case file.
    """
    with as_user(db, two_orgs["user_a"]) as s, pytest.raises(ProgrammingError):
        s.execute(
            text(
                "INSERT INTO cases (org_id, case_ref, status) "
                "VALUES (:o, 'CASE-EVIL-001', 'received')"
            ),
            {"o": two_orgs["org_b"]},
        )


def test_unauthenticated_session_sees_nothing(db: Session, two_orgs: dict) -> None:
    """With no user bound, every policy evaluates to false.

    Fails closed: a bug that forgets to bind the user yields an empty result,
    never the whole table.
    """
    db.rollback()
    db.begin()
    db.execute(text("SET LOCAL ROLE headwaters_app"))
    try:
        rows = db.execute(text("SELECT id FROM cases")).all()
    finally:
        db.rollback()
    assert rows == []


def test_superuser_bypasses_rls_which_is_why_tests_must_set_role(
    db: Session, two_orgs: dict
) -> None:
    """Documents the trap this suite is built to avoid.

    The `db` fixture connects as a SUPERUSER, and a superuser bypasses RLS
    unconditionally -- FORCE does not bind it. (FORCE *does* bind a plain table
    owner; see test_db_guards.py, which measures both.) A tenancy test written
    on this session would therefore pass with no policies at all, which is why
    every assertion above goes through `as_user`.
    """
    visible = {r[0] for r in db.execute(text("SELECT id FROM cases")).all()}
    assert {two_orgs["case_a"], two_orgs["case_b"]} <= visible


def test_evidence_chain_is_append_only(db: Session, two_orgs: dict) -> None:
    """UPDATE and DELETE on the custody log are revoked, not merely avoided.

    Code that "must not" rewrite history eventually does. A missing privilege
    cannot.
    """
    db.execute(
        text(
            """
            INSERT INTO evidence_events
                (org_id, case_id, seq, ts_utc, actor, action, payload_hash, entry_hash)
            VALUES (:o, :c, 0, now(), 'test', 'acquired', :h, :h)
            """
        ),
        {"o": two_orgs["org_a"], "c": two_orgs["case_a"], "h": "a" * 64},
    )
    db.commit()

    with as_user(db, two_orgs["user_a"]) as s, pytest.raises(ProgrammingError):
        s.execute(text("UPDATE evidence_events SET actor = 'tampered'"))

    with as_user(db, two_orgs["user_a"]) as s, pytest.raises(ProgrammingError):
        s.execute(text("DELETE FROM evidence_events"))


def test_every_tenant_table_has_rls_forced(db: Session) -> None:
    """A tenant table without RLS is a silent hole.

    Cross-checks the model registry against the live database, so adding a
    tenant table and forgetting its policy fails the build instead of shipping.
    """
    from app.models import TENANT_TABLES

    rows = db.execute(
        text(
            """
            SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                   (SELECT count(*) FROM pg_policies p
                     WHERE p.schemaname='public' AND p.tablename = c.relname)
              FROM pg_class c
             WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
            """
        )
    ).all()
    state = {r[0]: (r[1], r[2], r[3]) for r in rows}

    for table in TENANT_TABLES:
        assert table in state, f"{table} is missing from the database"
        enabled, forced, policies = state[table]
        assert enabled, f"{table}: row-level security is not enabled"
        assert forced, f"{table}: RLS not FORCEd, so the owner silently bypasses it"
        assert policies >= 1, f"{table}: RLS enabled but no policy -- denies everything"


def test_llm_cache_is_deliberately_not_tenant_scoped(db: Session) -> None:
    """Documents an intentional exception.

    The cache key is a hash of the complete prompt, so a hit is only possible
    for a byte-identical input; there is no cross-tenant inference. Sharing it is
    what lets a pre-warmed corpus answer offline.
    """
    from app.models import TENANT_TABLES

    assert "llm_cache" not in TENANT_TABLES
    enabled = db.execute(
        text("SELECT relrowsecurity FROM pg_class WHERE relname='llm_cache'")
    ).scalar()
    assert enabled is False
