"""Connection-privilege guards.

The tenancy design has exactly one catastrophic failure mode: the API connects
with a role that bypasses row-level security, every policy silently stops
applying, and the only thing standing between two customers' correspondence is
whether a developer remembered a ``WHERE org_id`` clause. Nothing fails, no
error is logged, and the leak is discovered by someone else.

So it is checked at startup and the process refuses to serve.

WHAT ACTUALLY BYPASSES RLS
--------------------------
Measured, not assumed (see tests/test_db_guards.py):

===========================  =======  ===================
role                         FORCE    rows visible
===========================  =======  ===================
non-superuser table owner    on       policy applies
non-superuser table owner    off      all rows
SUPERUSER                    on       all rows
role with BYPASSRLS          on       all rows
===========================  =======  ===================

``ALTER TABLE ... FORCE ROW LEVEL SECURITY`` *does* bind the table owner. What it
cannot bind is a **superuser** or a role holding **BYPASSRLS** -- those two
attributes defeat RLS unconditionally. Ownership is therefore not the thing to
check for; those two attributes are.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.logging import get_logger

log = get_logger(__name__)


class UnsafeConnectionError(RuntimeError):
    """Raised when a connection intended for user-facing work can bypass RLS."""


@dataclass(frozen=True, slots=True)
class ConnectionPrivileges:
    role: str
    is_superuser: bool
    has_bypassrls: bool

    @property
    def bypasses_rls(self) -> bool:
        """True when row-level security cannot constrain this connection."""
        return self.is_superuser or self.has_bypassrls


def inspect_privileges(engine: Engine) -> ConnectionPrivileges:
    """Report the RLS-relevant attributes of the connection's effective role."""
    with engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT current_user::text,
                       COALESCE(rolsuper, false),
                       COALESCE(rolbypassrls, false)
                  FROM pg_roles
                 WHERE rolname = current_user
                """
            )
        ).one()
    return ConnectionPrivileges(role=row[0], is_superuser=row[1], has_bypassrls=row[2])


def assert_rls_enforced(engine: Engine, *, label: str = "app") -> ConnectionPrivileges:
    """Refuse to continue if this connection can bypass row-level security.

    Called at API startup against the request-path engine. Failing loudly here
    is the whole point: the alternative is a service that starts cleanly and
    serves cross-tenant data.
    """
    privileges = inspect_privileges(engine)
    if privileges.bypasses_rls:
        raise UnsafeConnectionError(
            f"The {label} database connection authenticates as "
            f"'{privileges.role}', which bypasses row-level security "
            f"(superuser={privileges.is_superuser}, bypassrls={privileges.has_bypassrls}). "
            f"Every tenancy policy would silently stop applying. "
            f"Point DATABASE_URL_APP at an unprivileged role such as 'headwaters_app'."
        )
    log.info("db.rls_guard.ok", label=label, role=privileges.role)
    return privileges


def assert_privileged(engine: Engine, *, label: str = "system") -> ConnectionPrivileges:
    """The mirror image: confirm the system connection *can* do system work.

    The worker and the migration runner are deliberately privileged -- a worker
    is a system actor spanning every organisation. Checking this too means a
    swapped pair of URLs is caught at startup rather than manifesting later as
    an empty queue that nobody can explain.
    """
    privileges = inspect_privileges(engine)
    if not privileges.bypasses_rls:
        log.warning(
            "db.system_connection_is_constrained",
            role=privileges.role,
            note="worker will only see rows its role is permitted; check DATABASE_URL",
        )
    return privileges
