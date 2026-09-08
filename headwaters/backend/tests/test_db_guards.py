"""Connection-privilege enforcement.

These tests exist because the failure they guard against is silent. A request
path connected with a privileged role returns cross-tenant rows, raises nothing,
logs nothing, and looks like a working feature. Everything here converts that
into a loud failure at startup or at review time.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest
from app.db.guards import UnsafeConnectionError, assert_rls_enforced, inspect_privileges
from app.db.session import AppSessionLocal, SessionLocal, get_app_engine, get_engine, tenant_scope
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.conftest import requires_db

pytestmark = requires_db


# --------------------------------------------------------------- the premise
def test_force_rls_binds_a_plain_owner_but_not_a_superuser(db: Session) -> None:
    """The measurement the whole guard rests on.

    ``FORCE ROW LEVEL SECURITY`` *does* constrain a plain table owner -- so
    ownership is not what we need to defend against. What it cannot constrain is
    a SUPERUSER (or a role holding BYPASSRLS). If a future Postgres changed
    either behaviour, ``assert_rls_enforced`` would be checking the wrong
    attribute, and this test would fail rather than the product leaking.
    """
    db.rollback()
    db.execute(text("DROP TABLE IF EXISTS rls_probe"))
    db.execute(text("DROP ROLE IF EXISTS rls_probe_owner"))
    db.execute(text("CREATE ROLE rls_probe_owner NOSUPERUSER NOBYPASSRLS"))
    db.execute(text("GRANT USAGE ON SCHEMA public TO rls_probe_owner"))
    db.execute(text("CREATE TABLE rls_probe (id int, org text)"))
    db.execute(text("INSERT INTO rls_probe VALUES (1,'a'),(2,'b')"))
    db.execute(text("ALTER TABLE rls_probe OWNER TO rls_probe_owner"))
    db.execute(text("ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY"))
    db.execute(text("ALTER TABLE rls_probe FORCE ROW LEVEL SECURITY"))
    db.execute(text("CREATE POLICY p ON rls_probe USING (org = 'a')"))
    db.commit()

    try:
        superuser_sees = db.execute(text("SELECT count(*) FROM rls_probe")).scalar_one()

        db.execute(text("SET ROLE rls_probe_owner"))
        owner_sees = db.execute(text("SELECT count(*) FROM rls_probe")).scalar_one()
        db.execute(text("RESET ROLE"))

        assert owner_sees == 1, "FORCE ROW LEVEL SECURITY must constrain a plain owner"
        assert superuser_sees == 2, "a superuser is expected to bypass RLS even with FORCE"
    finally:
        db.rollback()
        db.execute(text("DROP TABLE IF EXISTS rls_probe"))
        db.execute(text("REVOKE ALL ON SCHEMA public FROM rls_probe_owner"))
        db.execute(text("DROP ROLE IF EXISTS rls_probe_owner"))
        db.commit()


# ------------------------------------------------------- the two connections
def test_request_path_connection_cannot_bypass_rls() -> None:
    """The single most important assertion in the suite."""
    privileges = inspect_privileges(get_app_engine())
    assert not privileges.is_superuser, f"request path connects as superuser '{privileges.role}'"
    assert not privileges.has_bypassrls, f"'{privileges.role}' holds BYPASSRLS"
    assert not privileges.bypasses_rls


def test_startup_guard_refuses_a_privileged_connection() -> None:
    """Point the guard at the system engine: it must refuse, with a fix in the
    message. This is what protects a misconfigured deploy."""
    with pytest.raises(UnsafeConnectionError) as exc:
        assert_rls_enforced(get_engine(), label="request-path")

    message = str(exc.value)
    assert "bypasses row-level security" in message
    assert "DATABASE_URL_APP" in message, "the error must name the setting to change"


def test_system_connection_is_privileged_on_purpose() -> None:
    """The worker must span every organisation; a constrained system connection
    would silently drain nothing."""
    assert inspect_privileges(get_engine()).bypasses_rls


# ------------------------------------------------------------ session safety
def test_tenant_scope_refuses_a_system_session() -> None:
    """Using the privileged session for user work is the mistake that leaks.

    It cannot be caught at runtime by observation -- the query succeeds and
    returns every organisation's rows -- so it is refused structurally.
    """
    session = SessionLocal()
    try:
        with (
            pytest.raises(RuntimeError, match="privileged system session"),
            tenant_scope(session, uuid.uuid4()),
        ):
            pass
    finally:
        session.close()


def test_tenant_scope_accepts_an_app_session(two_orgs: dict) -> None:
    session = AppSessionLocal()
    try:
        with tenant_scope(session, two_orgs["user_a"]) as scoped:
            visible = {r[0] for r in scoped.execute(text("SELECT id FROM cases")).all()}
        assert two_orgs["case_a"] in visible
        assert two_orgs["case_b"] not in visible
    finally:
        session.close()


def test_app_session_alone_still_isolates_without_an_explicit_role_switch(
    two_orgs: dict,
) -> None:
    """Belt and braces are both real.

    ``tenant_scope`` issues ``SET LOCAL ROLE`` as a second layer, but the
    connection is already unprivileged -- so isolation holds on the GUC alone.
    Losing one layer must not lose the protection.
    """
    session = AppSessionLocal()
    try:
        session.begin()
        session.execute(
            text("SELECT set_config('app.current_user_id', :u, true)"),
            {"u": str(two_orgs["user_a"])},
        )
        visible = {r[0] for r in session.execute(text("SELECT id FROM cases")).all()}
        assert two_orgs["case_b"] not in visible
    finally:
        session.rollback()
        session.close()


# ------------------------------------------------- architectural enforcement
#: Names that hand a router a SESSION on which row-level security does not
#: apply. Importing any of these into a request handler is the mistake that
#: leaks, so it is forbidden outright.
_FORBIDDEN_IN_ROUTERS = frozenset({"SessionLocal", "_system_factory", "_app_factory"})

#: Engine handles are a different thing: they open no session and return no
#: rows. `/readyz` legitimately probes both connections, and reporting only the
#: system one would show a healthy service that cannot serve an authenticated
#: read. The exemption is narrow, named, and justified here rather than being an
#: unexplained hole in the rule.
_ENGINE_ACCESS_ALLOWED_IN = frozenset({"health.py"})
_ENGINE_NAMES = frozenset({"get_engine", "get_app_engine"})


def test_routers_never_acquire_a_privileged_session() -> None:
    """A fitness function, not a style rule.

    A router that opens a system session gets a connection on which RLS does not
    apply. The handler looks correct, raises nothing, and returns every
    organisation's rows. Convention will not hold that line across a team and a
    deadline, so it is asserted.
    """
    routers = Path(__file__).resolve().parent.parent / "app" / "routers"
    offenders: list[str] = []

    for module in routers.rglob("*.py"):
        tree = ast.parse(module.read_text(), filename=str(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "app.db.session":
                for alias in node.names:
                    if alias.name in _FORBIDDEN_IN_ROUTERS:
                        offenders.append(f"{module.name} imports {alias.name}")
                    elif (
                        alias.name in _ENGINE_NAMES and module.name not in _ENGINE_ACCESS_ALLOWED_IN
                    ):
                        allowed = sorted(_ENGINE_ACCESS_ALLOWED_IN)
                        offenders.append(
                            f"{module.name} imports {alias.name} "
                            f"(engine access allowed only in {allowed})"
                        )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "app.db.session":
                        offenders.append(
                            f"{module.name} imports app.db.session wholesale, "
                            "which reaches the privileged factory"
                        )

    assert not offenders, (
        "routers must obtain sessions via app.security.deps.get_tenant_db, "
        f"never the privileged system connection: {offenders}"
    )


def test_bootstrap_leaves_the_evidence_chain_append_only(db: Session, two_orgs: dict) -> None:
    """Ordering regression guard.

    ``bootstrap`` re-runs a blanket GRANT and then re-applies the REVOKE on
    ``evidence_events``. Reversing those two statements would silently restore
    UPDATE and DELETE on the chain of custody, and nothing else would notice.
    """
    from app.db.bootstrap import bootstrap_app_role

    bootstrap_app_role(get_engine(), password=None)

    granted = (
        db.execute(
            text(
                """
            SELECT privilege_type FROM information_schema.role_table_grants
             WHERE grantee = 'headwaters_app' AND table_name = 'evidence_events'
            """
            )
        )
        .scalars()
        .all()
    )

    assert "INSERT" in granted, "the chain must still be appendable"
    assert "SELECT" in granted, "the chain must still be readable"
    assert "UPDATE" not in granted, "bootstrap re-granted UPDATE on the custody log"
    assert "DELETE" not in granted, "bootstrap re-granted DELETE on the custody log"
