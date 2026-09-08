"""Seed the demo tenant.

Idempotent, and skipped entirely in production. Exists so the stack is usable
the moment it starts: a case list with nothing in it demonstrates nothing, and
the campaign correlation this product is built around is meaningless without a
corpus to correlate against.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.security.identity import DEMO_ORG_ID, DEMO_ORG_SLUG, DEMO_USER_EMAIL, DEMO_USER_ID

log = get_logger(__name__)


def seed_demo_tenant(db: Session) -> None:
    """Create the demo organisation, analyst and membership if absent."""
    db.execute(
        text(
            """
            INSERT INTO orgs (id, name, slug, settings)
            VALUES (:id, 'Kaveri Financial Services Ltd', :slug,
                    CAST(:settings AS jsonb))
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {
            "id": str(DEMO_ORG_ID),
            "slug": DEMO_ORG_SLUG,
            "settings": '{"protected_domains":["kaverifs.com"],'
            '"protected_identities":["Anand Rao","CEO","CFO"]}',
        },
    )
    db.execute(
        text(
            """
            INSERT INTO users (id, email, display_name)
            VALUES (:id, :email, 'Priya Menon')
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"id": str(DEMO_USER_ID), "email": DEMO_USER_EMAIL},
    )
    db.execute(
        text(
            """
            INSERT INTO memberships (org_id, user_id, role)
            VALUES (:org, :user, 'analyst')
            ON CONFLICT DO NOTHING
            """
        ),
        {"org": str(DEMO_ORG_ID), "user": str(DEMO_USER_ID)},
    )
    db.commit()
    log.info("demo.tenant_seeded", org=str(DEMO_ORG_ID))
