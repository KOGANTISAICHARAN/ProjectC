"""Chain-of-custody endpoints.

``/verify`` is the one a judge, an auditor or opposing counsel actually uses: it
recomputes every hash, every link and every signature and reports the exact
event that broke, if any.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.security.deps import get_tenant_db
from app.security.identity import resolve_user_id
from app.services.evidence.chain import verify_chain

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["evidence"])


def tenant_session(user_id: Annotated[uuid.UUID, Depends(resolve_user_id)]) -> Any:
    yield from get_tenant_db(user_id)


TenantDb = Annotated[Session, Depends(tenant_session)]


class EventOut(BaseModel):
    seq: int
    ts_utc: str
    actor: str
    action: str
    payload_hash: str
    prev_hash: str | None
    entry_hash: str
    signing_key_id: str | None
    metadata: dict[str, Any]


class LinkOut(BaseModel):
    seq: int
    action: str
    entry_hash: str
    hash_ok: bool
    link_ok: bool
    signature_ok: bool
    ok: bool
    reason: str | None


class VerifyOut(BaseModel):
    case_id: uuid.UUID
    intact: bool
    event_count: int
    merkle_root: str | None
    signing_key_id: str
    public_key: str
    first_broken_seq: int | None
    summary: str
    links: list[LinkOut]


@router.get("/cases/{case_id}/evidence", response_model=list[EventOut])
def get_evidence(case_id: uuid.UUID, db: TenantDb) -> list[EventOut]:
    rows = db.execute(
        text(
            """
            SELECT seq, ts_utc, actor, action, payload_hash, prev_hash, entry_hash,
                   signing_key_id, metadata
              FROM evidence_events WHERE case_id = :c ORDER BY seq
            """
        ),
        {"c": str(case_id)},
    ).all()
    return [
        EventOut(
            seq=r[0],
            ts_utc=r[1].isoformat(),
            actor=r[2],
            action=r[3],
            payload_hash=r[4],
            prev_hash=r[5],
            entry_hash=r[6],
            signing_key_id=r[7],
            metadata=r[8] or {},
        )
        for r in rows
    ]


@router.post("/cases/{case_id}/evidence/verify", response_model=VerifyOut)
def verify_evidence(case_id: uuid.UUID, db: TenantDb) -> VerifyOut:
    result = verify_chain(db, case_id)
    if result.event_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No evidence recorded for this case",
        )
    return VerifyOut(
        case_id=result.case_id,
        intact=result.intact,
        event_count=result.event_count,
        merkle_root=result.merkle_root,
        signing_key_id=result.signing_key_id,
        public_key=result.public_key,
        first_broken_seq=result.first_broken_seq,
        summary=result.summary,
        links=[
            LinkOut(
                seq=link.seq,
                action=link.action,
                entry_hash=link.entry_hash,
                hash_ok=link.hash_ok,
                link_ok=link.link_ok,
                signature_ok=link.signature_ok,
                ok=link.ok,
                reason=link.reason,
            )
            for link in result.links
        ],
    )


@router.post("/cases/{case_id}/evidence/tamper", tags=["demo"])
def tamper_evidence(case_id: uuid.UUID, seq: int = 2) -> dict[str, Any]:
    """Deliberately corrupt one stored event, to demonstrate detection.

    The privileged operation lives in ``services.evidence.demo``: routers may
    not reach the system connection, and a function that intentionally corrupts
    evidence belongs somewhere obvious.
    """
    from app.services.evidence.demo import TamperUnavailableError, tamper_with_event

    try:
        tamper_with_event(case_id, seq)
    except TamperUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The tamper endpoint is disabled outside development",
        ) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return {
        "tampered_seq": seq,
        "note": (
            "One field of a stored event was altered using the privileged system "
            "connection. The application role could not have done this: UPDATE and "
            "DELETE on evidence_events are revoked from it. Re-run verify."
        ),
    }
