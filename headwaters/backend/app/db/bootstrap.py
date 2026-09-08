"""Idempotent database bootstrap.

Runs after migrations, before the API accepts traffic. Migrations create the
application role ``NOLOGIN`` -- a credential must never live in a migration file
-- so something has to grant it a password from the secret store. That is this.

Also re-applies the grant/revoke pair, because ``GRANT ... ON ALL TABLES`` only
covers tables that existed when it ran. ``ALTER DEFAULT PRIVILEGES`` handles
tables created afterwards by the same role, but re-applying is cheap and makes
the privilege state a function of this file rather than of migration history.

Order matters: grant first, then revoke on ``evidence_events``. Reversing them
would silently restore UPDATE and DELETE on the chain of custody.
"""

from __future__ import annotations

import sys

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import APP_ROLE, get_engine

log = get_logger(__name__)


def bootstrap_app_role(engine: Engine, password: str | None) -> None:
    """Give the application role a login credential and its table grants."""
    with engine.begin() as conn:
        # APP_ROLE is a module constant, never user input; the only value that
        # comes from outside is the password, which is escaped by Postgres's own
        # quote_literal() below rather than interpolated here.
        conn.execute(
            text(
                f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                        CREATE ROLE {APP_ROLE} NOLOGIN;
                    END IF;
                END
                $$;
                """  # noqa: S608 - APP_ROLE is a module constant, never user input
            )
        )

        if password:
            # Parameterised through format(): ALTER ROLE takes no bind params,
            # and quote_literal() is Postgres's own escaping, so the password is
            # never concatenated into SQL by Python.
            # Build the statement inside Postgres with quote_literal() so the
            # password is escaped by the server, never concatenated by Python.
            # ALTER ROLE accepts no bind parameters, so this two-step is the
            # safe way to do it.
            stmt = conn.execute(
                text(
                    f"SELECT format('ALTER ROLE {APP_ROLE} LOGIN PASSWORD %s', quote_literal(:pw))"
                ),
                {"pw": password},
            ).scalar_one()
            conn.execute(text(stmt))
            log.info("db.bootstrap.role_login_granted", role=APP_ROLE)
        else:
            log.warning(
                "db.bootstrap.no_password",
                role=APP_ROLE,
                note="role remains NOLOGIN; set APP_DB_PASSWORD before deploying",
            )

        for stmt_sql in (
            f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}",
            f"GRANT USAGE ON SCHEMA app TO {APP_ROLE}",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}",
            f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app TO {APP_ROLE}",
            # Must come last: the blanket grant above would otherwise hand back
            # write access to the append-only chain of custody.
            f"REVOKE UPDATE, DELETE ON evidence_events FROM {APP_ROLE}",
        ):
            conn.execute(text(stmt_sql))

    log.info("db.bootstrap.complete", role=APP_ROLE)


def main() -> int:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=settings.environment != "local")
    try:
        bootstrap_app_role(get_engine(), settings.app_db_password)
    except Exception as exc:
        log.exception("db.bootstrap.failed", error=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
