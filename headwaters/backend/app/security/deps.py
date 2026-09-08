"""FastAPI dependencies.

``get_tenant_db`` is the **only** sanctioned way for a router to obtain a
database session. It yields a session that is unprivileged, bound to the calling
analyst, and inside a transaction -- so row-level security applies to every
statement the handler runs.

Routers must never import ``SessionLocal``: that is the privileged system
connection, and a handler using it would return rows from every organisation
while looking entirely correct. ``tests/test_db_guards.py`` enforces this as an
architectural rule rather than a convention.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

from sqlalchemy.orm import Session

from app.db.session import AppSessionLocal, tenant_scope


def get_tenant_db(user_id: uuid.UUID) -> Iterator[Session]:
    """Yield an RLS-constrained session bound to ``user_id``.

    Authentication (Phase 8) will resolve ``user_id`` from the verified Supabase
    JWT and wire this as a proper ``Depends``. The signature is settled now so
    routers written before then cannot acquire a session any other way.
    """
    session = AppSessionLocal()
    try:
        with tenant_scope(session, user_id) as scoped:
            yield scoped
    finally:
        session.close()
