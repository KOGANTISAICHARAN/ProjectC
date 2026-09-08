"""row level security and app role

Revision ID: 75398574be98
Revises: e8de20c22fae
Create Date: 2026-09-04 05:17:59.891717
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "75398574be98"
down_revision: str | None = "e8de20c22fae"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Tables holding customer data. Kept in sync with app.models.TENANT_TABLES by a
# test -- adding a tenant table without a policy is a tenancy bug, and a silent
# one, so it fails the build rather than leaking.
TENANT_TABLES = (
    "cases",
    "email_artifacts",
    "email_headers",
    "received_hops",
    "auth_results",
    "origin_assessment",
    "indicators",
    "findings",
    "ai_analysis",
    "dna_fingerprints",
    "graph_nodes",
    "graph_edges",
    "campaigns",
    "campaign_members",
    "jobs",
    "evidence_events",
    "reports",
)

APP_ROLE = "headwaters_app"


def upgrade() -> None:
    # ------------------------------------------------------------------ role
    # The application must NOT connect as the table owner or a superuser: both
    # bypass row-level security, which would make every policy below decorative.
    # Locally the tests reach this role with SET ROLE; in production DATABASE_URL
    # authenticates as it directly (see docs/RUNBOOK.md, "Database roles").
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} NOLOGIN;
            END IF;
        END
        $$;
        """
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}")
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}"
    )

    # ------------------------------------------------- current-user resolution
    # Portable across a plain Postgres container and Supabase. The GUC is what
    # the application sets per request (SET LOCAL, so it is transaction-scoped
    # and cannot leak to the next request on a pooled connection). The JWT claim
    # is what Supabase's PostgREST sets when a client reaches the database.
    op.execute("CREATE SCHEMA IF NOT EXISTS app")
    op.execute(f"GRANT USAGE ON SCHEMA app TO {APP_ROLE}")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS uuid
        LANGUAGE sql STABLE
        AS $$
            SELECT COALESCE(
                NULLIF(current_setting('app.current_user_id', true), '')::uuid,
                NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
            )
        $$;
        """
    )

    # SECURITY DEFINER, and this is load-bearing rather than a convenience.
    #
    # Every tenant policy needs to ask "which orgs does this user belong to?",
    # which means reading `memberships`. But `memberships` is itself RLS-
    # protected, and its policy asks the same question -- so a policy written as
    # a plain subquery recurses infinitely and Postgres aborts the statement with
    # "infinite recursion detected in policy for relation memberships".
    #
    # A SECURITY DEFINER function executes as its owner, which bypasses RLS for
    # that one lookup and breaks the cycle. `search_path` is pinned because a
    # SECURITY DEFINER function with a caller-controlled search_path is a
    # privilege-escalation primitive: an attacker who can create objects could
    # otherwise shadow `memberships` with their own table.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.user_org_ids() RETURNS SETOF uuid
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT org_id FROM memberships WHERE user_id = app.current_user_id()
        $$;
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.colleague_ids() RETURNS SETOF uuid
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = public, pg_temp
        AS $$
            SELECT DISTINCT m2.user_id
              FROM memberships m1
              JOIN memberships m2 ON m2.org_id = m1.org_id
             WHERE m1.user_id = app.current_user_id()
        $$;
        """
    )
    op.execute(f"GRANT EXECUTE ON FUNCTION app.current_user_id() TO {APP_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION app.user_org_ids() TO {APP_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION app.colleague_ids() TO {APP_ROLE}")

    # --------------------------------------------------------------- policies
    for stmt in (
        "ALTER TABLE orgs ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE orgs FORCE ROW LEVEL SECURITY",
        "CREATE POLICY orgs_member_read ON orgs FOR SELECT "
        "USING (id IN (SELECT app.user_org_ids()))",
        "ALTER TABLE memberships ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE memberships FORCE ROW LEVEL SECURITY",
        "CREATE POLICY memberships_own_org ON memberships FOR SELECT "
        "USING (org_id IN (SELECT app.user_org_ids()))",
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE users FORCE ROW LEVEL SECURITY",
        # An analyst may resolve themselves and colleagues in a shared org: case
        # attribution is meaningless if you cannot say who acted.
        "CREATE POLICY users_self_or_colleague ON users FOR SELECT "
        "USING (id = app.current_user_id() OR id IN (SELECT app.colleague_ids()))",
    ):
        op.execute(stmt)

    # Every other tenant table reduces to the same predicate: you may touch a
    # row only if you belong to the organisation that owns it. One template
    # applied uniformly is far easier to audit than seventeen bespoke rules.
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE matters: without it the table OWNER bypasses RLS, and in local
        # development the owner is the same role that runs the tests -- the
        # policies would appear to work while never being exercised.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_org_isolation ON {table}
            USING (org_id IN (SELECT app.user_org_ids()))
            WITH CHECK (org_id IN (SELECT app.user_org_ids()))
            """
        )

    # ------------------------------------------------------- append-only chain
    # The evidence chain is append-only. Enforced by a revoked grant, not by
    # convention: code that "must not" mutate history eventually does, whereas a
    # missing privilege cannot. A tampered chain must be detectable, but it is
    # better if the application is incapable of producing one in the first place.
    op.execute(f"REVOKE UPDATE, DELETE ON evidence_events FROM {APP_ROLE}")

    # llm_cache holds no customer data -- its key is a hash of the full prompt,
    # so a hit is only possible for a byte-identical input. No RLS, and shared
    # deliberately: that is what makes a pre-warmed corpus useful offline.


def downgrade() -> None:
    op.execute("GRANT UPDATE, DELETE ON evidence_events TO " + APP_ROLE)
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_org_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    for table, policy in (
        ("users", "users_self_or_colleague"),
        ("memberships", "memberships_own_org"),
        ("orgs", "orgs_member_read"),
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP FUNCTION IF EXISTS app.colleague_ids()")
    op.execute("DROP FUNCTION IF EXISTS app.user_org_ids()")
    op.execute("DROP FUNCTION IF EXISTS app.current_user_id()")
    op.execute("DROP SCHEMA IF EXISTS app")
    # The role is intentionally NOT dropped: it may own grants in other
    # databases, and dropping a role out from under a live connection string is
    # a worse failure than leaving an unused role behind.
