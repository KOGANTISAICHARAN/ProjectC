"""The chain of custody.

Every analysis stage and every analyst action appends one event:

    entry_hash = SHA256(canonical_json({
        seq, case_id, ts_utc, actor, action, payload_hash, prev_hash
    }))

Altering event 4 makes 5, 6 and 7 fail verification, and the verifier names the
exact link that broke.

Append-only is enforced by Postgres, not by convention: ``UPDATE`` and ``DELETE``
on ``evidence_events`` are revoked from the application role. Code that must not
rewrite history eventually does; a missing privilege cannot.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.enums import EvidenceAction
from app.services.evidence.canonical import canonical_hash
from app.services.evidence.merkle import merkle_root
from app.services.evidence.signing import Signer

log = get_logger(__name__)


@dataclass(slots=True)
class LinkResult:
    seq: int
    action: str
    ts_utc: str
    actor: str
    entry_hash: str
    prev_hash: str | None
    hash_ok: bool
    link_ok: bool
    signature_ok: bool
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.hash_ok and self.link_ok and self.signature_ok


@dataclass(slots=True)
class VerificationResult:
    case_id: uuid.UUID
    intact: bool
    event_count: int
    merkle_root: str | None
    signing_key_id: str
    public_key: str
    links: list[LinkResult]
    first_broken_seq: int | None
    summary: str


def compute_entry_hash(
    *,
    seq: int,
    case_id: uuid.UUID | str,
    ts_utc: datetime,
    actor: str,
    action: str,
    payload_hash: str,
    prev_hash: str | None,
) -> str:
    """The one definition. Both append and verify call this, so a change to the
    formula can never make new events verify against an old rule."""
    return canonical_hash(
        {
            "seq": seq,
            "case_id": str(case_id),
            "ts_utc": ts_utc,
            "actor": actor,
            "action": action,
            "payload_hash": payload_hash,
            "prev_hash": prev_hash,
        }
    )


def append_event(
    db: Session,
    *,
    org_id: uuid.UUID,
    case_id: uuid.UUID,
    actor: str,
    action: EvidenceAction,
    payload: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    ts_utc: datetime | None = None,
) -> str:
    """Append one event and return its entry hash.

    Does not commit: the caller owns the transaction, so a stage's work and its
    custody record either both land or neither does.
    """
    signer = Signer.from_settings()
    timestamp = ts_utc or datetime.now(UTC)

    previous = db.execute(
        text(
            "SELECT seq, entry_hash FROM evidence_events WHERE case_id = :c "
            "ORDER BY seq DESC LIMIT 1"
        ),
        {"c": str(case_id)},
    ).first()
    seq = (previous[0] + 1) if previous else 0
    prev_hash = previous[1] if previous else None

    payload_hash = canonical_hash(payload)
    entry_hash = compute_entry_hash(
        seq=seq,
        case_id=case_id,
        ts_utc=timestamp,
        actor=actor,
        action=action.value,
        payload_hash=payload_hash,
        prev_hash=prev_hash,
    )

    db.execute(
        text(
            """
            INSERT INTO evidence_events (org_id, case_id, seq, ts_utc, actor, action,
                payload_hash, metadata, prev_hash, entry_hash, signature, signing_key_id)
            VALUES (:org, :case, :seq, :ts, :actor, :action, :phash,
                    CAST(:meta AS jsonb), :prev, :entry, :sig, :kid)
            """
        ),
        {
            "org": str(org_id),
            "case": str(case_id),
            "seq": seq,
            "ts": timestamp,
            "actor": actor,
            "action": action.value,
            "phash": payload_hash,
            "meta": _json(metadata or {}),
            "prev": prev_hash,
            "entry": entry_hash,
            "sig": signer.sign(entry_hash),
            "kid": signer.key_id,
        },
    )
    return entry_hash


def verify_chain(db: Session, case_id: uuid.UUID) -> VerificationResult:
    """Recompute every hash, every link and every signature.

    Three independent checks per event:

    * **hash** -- does the stored ``entry_hash`` match a recomputation from the
      stored fields? Detects an altered event.
    * **link** -- does ``prev_hash`` equal the previous event's ``entry_hash``?
      Detects a removed or reordered event.
    * **signature** -- does the Ed25519 signature verify? Detects an event
      forged by someone without the key.
    """
    signer = Signer.from_settings()
    rows = db.execute(
        text(
            """
            SELECT seq, ts_utc, actor, action, payload_hash, prev_hash, entry_hash,
                   signature
              FROM evidence_events WHERE case_id = :c ORDER BY seq
            """
        ),
        {"c": str(case_id)},
    ).all()

    links: list[LinkResult] = []
    expected_prev: str | None = None
    first_broken: int | None = None

    for index, row in enumerate(rows):
        seq, ts, actor, action, payload_hash, prev_hash, entry_hash, signature = row

        recomputed = compute_entry_hash(
            seq=seq,
            case_id=case_id,
            ts_utc=ts,
            actor=actor,
            action=action,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
        )
        hash_ok = recomputed == entry_hash
        link_ok = (prev_hash == expected_prev) and seq == index
        signature_ok = signer.verify(entry_hash, signature)

        reason = None
        if not hash_ok:
            reason = "entry hash does not match a recomputation from the stored fields"
        elif not link_ok:
            reason = "prev_hash does not match the preceding event, or the sequence has a gap"
        elif not signature_ok:
            reason = "signature does not verify under the current signing key"

        links.append(
            LinkResult(
                seq=seq,
                action=action,
                ts_utc=ts.isoformat(),
                actor=actor,
                entry_hash=entry_hash,
                prev_hash=prev_hash,
                hash_ok=hash_ok,
                link_ok=link_ok,
                signature_ok=signature_ok,
                reason=reason,
            )
        )
        if first_broken is None and not links[-1].ok:
            first_broken = seq
        expected_prev = entry_hash

    intact = all(link.ok for link in links) and bool(links)
    root = merkle_root([link.entry_hash for link in links])

    if not links:
        summary = "No evidence events recorded for this case."
    elif intact:
        summary = (
            f"All {len(links)} events verify: every hash recomputes, every link "
            f"matches its predecessor, and every signature is valid under key "
            f"{signer.key_id}."
        )
    else:
        broken = next(link for link in links if not link.ok)
        summary = (
            f"Chain BROKEN at event {broken.seq} ({broken.action}): {broken.reason}. "
            f"Events after this point cannot be relied upon."
        )

    log.info("evidence.verified", case_id=str(case_id), intact=intact, events=len(links))

    return VerificationResult(
        case_id=case_id,
        intact=intact,
        event_count=len(links),
        merkle_root=root,
        signing_key_id=signer.key_id,
        public_key=signer.public_key_b64(),
        links=links,
        first_broken_seq=first_broken,
        summary=summary,
    )


def _json(value: dict[str, Any]) -> str:
    from app.services.evidence.canonical import canonical_json

    return canonical_json(value)
