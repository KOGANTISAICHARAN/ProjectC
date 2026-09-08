"""Case ingest."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.conftest import requires_db

pytestmark = requires_db


def test_case_ref_survives_a_deleted_case(db: Session, two_orgs: dict) -> None:
    """Regression: references were generated from count(*).

    Delete one case and the count no longer matches the highest suffix, so the
    next reference collides with one that already exists and the whole ingest
    fails with a unique-constraint violation. Gaps in case numbering are normal;
    re-using a reference is not, because analysts quote them aloud and in
    reports.
    """
    from app.services.ingest import _next_case_ref

    org = two_orgs["org_a"]
    year = datetime.now(UTC).year

    for suffix in (1, 2, 3):
        db.execute(
            text("INSERT INTO cases (org_id, case_ref, status) VALUES (:o, :r, 'complete')"),
            {"o": str(org), "r": f"CASE-{year}-{suffix:04d}"},
        )
    db.commit()

    # Remove the middle one, exactly as happened in practice.
    db.execute(
        text("DELETE FROM cases WHERE org_id = :o AND case_ref = :r"),
        {"o": str(org), "r": f"CASE-{year}-0002"},
    )
    db.commit()

    nxt = _next_case_ref(db, org)
    assert nxt == f"CASE-{year}-0004", "must continue past the highest, not fill the gap"

    existing = {
        r[0]
        for r in db.execute(
            text("SELECT case_ref FROM cases WHERE org_id = :o"), {"o": str(org)}
        ).all()
    }
    assert nxt not in existing
