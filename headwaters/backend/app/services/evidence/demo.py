"""Deliberate tampering, for demonstrating detection.

Isolated in a service rather than inlined in a router for two reasons. Routers
must never reach the privileged system connection -- an architectural rule a test
enforces -- and a function that intentionally corrupts evidence should live in
exactly one obvious, greppable place rather than being buried in an HTTP handler.
"""

from __future__ import annotations

import uuid

from sqlalchemy import text

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import SessionLocal

log = get_logger(__name__)


class TamperUnavailableError(RuntimeError):
    """Raised when tampering is attempted outside development."""


def tamper_with_event(case_id: uuid.UUID, seq: int) -> None:
    """Corrupt one stored evidence event so verification will fail.

    Uses the PRIVILEGED system connection on purpose. The application role has
    ``UPDATE`` and ``DELETE`` revoked on ``evidence_events`` and therefore
    *cannot* perform this operation through the normal path -- which is the point
    the demonstration is making.
    """
    if get_settings().is_production:
        raise TamperUnavailableError("disabled outside development")

    with SessionLocal() as system_db:
        updated = system_db.execute(
            text(
                "UPDATE evidence_events SET actor = actor || '-TAMPERED' "
                "WHERE case_id = :c AND seq = :s RETURNING seq"
            ),
            {"c": str(case_id), "s": seq},
        ).first()
        system_db.commit()

    if updated is None:
        raise LookupError(f"no evidence event at seq {seq}")

    log.warning("evidence.tampered_for_demo", case_id=str(case_id), seq=seq)
