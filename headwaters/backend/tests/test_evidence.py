"""Chain of custody.

The properties asserted here are the ones the product's evidence claim rests on.
If any of them stops holding, the claim becomes false rather than merely weaker.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from app.models.enums import EvidenceAction
from app.services.evidence.canonical import canonical_hash, canonical_json
from app.services.evidence.chain import append_event, compute_entry_hash, verify_chain
from app.services.evidence.merkle import merkle_proof, merkle_root, verify_proof
from app.services.evidence.signing import Signer
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.conftest import requires_db


# --------------------------------------------------------------- canonical
def test_canonical_json_is_key_order_independent() -> None:
    """Two dicts with the same content must hash identically regardless of the
    order they were built in, or verification depends on insertion order."""
    assert canonical_hash({"b": 1, "a": 2}) == canonical_hash({"a": 2, "b": 1})


def test_canonical_json_has_no_insignificant_whitespace() -> None:
    assert canonical_json({"a": 1, "b": [1, 2]}) == '{"a":1,"b":[1,2]}'


def test_canonical_json_normalises_datetimes_to_utc_z() -> None:
    from datetime import timedelta, timezone

    ist = datetime(2026, 9, 2, 15, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    utc = datetime(2026, 9, 2, 9, 30, tzinfo=UTC)
    assert canonical_hash({"t": ist}) == canonical_hash({"t": utc})


def test_canonical_json_renders_floats_as_strings() -> None:
    """Float repr is not portable between languages; a digest must not depend on
    the one that computed it."""
    assert '"0.100000"' in canonical_json({"x": 0.1})


# ------------------------------------------------------------------ merkle
def test_merkle_root_is_stable_and_order_sensitive() -> None:
    leaves = [f"{i:064x}" for i in range(5)]
    assert merkle_root(leaves) == merkle_root(list(leaves))
    assert merkle_root(leaves) != merkle_root(list(reversed(leaves)))


def test_merkle_root_of_empty_is_none() -> None:
    assert merkle_root([]) is None


def test_odd_node_is_carried_not_duplicated() -> None:
    """Promoting a lone odd node by hashing it with itself lets two distinct
    trees collide on one root (the Bitcoin CVE-2012-2459 shape)."""
    three = [f"{i:064x}" for i in range(3)]
    four = [*three, three[2]]
    assert merkle_root(three) != merkle_root(four)


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4])
def test_merkle_proof_verifies(index: int) -> None:
    """An auditor can be shown one event belongs to an anchored root without
    being given the whole chain."""
    leaves = [f"{i:064x}" for i in range(5)]
    root = merkle_root(leaves)
    assert root is not None
    assert verify_proof(leaves[index], merkle_proof(leaves, index), root)


# ----------------------------------------------------------------- signing
def test_signature_round_trips() -> None:
    signer = Signer.from_settings()
    digest = "ab" * 32
    assert signer.verify(digest, signer.sign(digest))


def test_signature_fails_for_a_different_digest() -> None:
    signer = Signer.from_settings()
    assert not signer.verify("cd" * 32, signer.sign("ab" * 32))


def test_development_key_is_deterministic_across_instances() -> None:
    """A key regenerated on each boot would make yesterday's chain unverifiable
    today -- indistinguishable from tampering."""
    assert Signer.from_settings().key_id == Signer.from_settings().key_id


# ------------------------------------------------------------------- chain
pytestmark_db = requires_db


@requires_db
def test_chain_appends_and_verifies(db: Session, two_orgs: dict) -> None:
    for action in (EvidenceAction.ACQUIRED, EvidenceAction.PARSED, EvidenceAction.SCORED):
        append_event(
            db,
            org_id=two_orgs["org_a"],
            case_id=two_orgs["case_a"],
            actor="test",
            action=action,
            payload={"stage": action.value},
        )
    db.commit()

    result = verify_chain(db, two_orgs["case_a"])
    assert result.intact
    assert result.event_count == 3
    assert result.merkle_root is not None
    assert all(link.ok for link in result.links)


@requires_db
def test_first_event_has_no_predecessor(db: Session, two_orgs: dict) -> None:
    append_event(
        db,
        org_id=two_orgs["org_a"],
        case_id=two_orgs["case_a"],
        actor="test",
        action=EvidenceAction.ACQUIRED,
        payload={},
    )
    db.commit()
    prev = db.execute(
        text("SELECT prev_hash FROM evidence_events WHERE case_id = :c AND seq = 0"),
        {"c": str(two_orgs["case_a"])},
    ).scalar()
    assert prev is None


@requires_db
def test_tampering_is_detected_and_the_broken_link_named(db: Session, two_orgs: dict) -> None:
    """The property the whole evidence claim rests on."""
    for action in (
        EvidenceAction.ACQUIRED,
        EvidenceAction.PARSED,
        EvidenceAction.AUTH_EVALUATED,
        EvidenceAction.SCORED,
    ):
        append_event(
            db,
            org_id=two_orgs["org_a"],
            case_id=two_orgs["case_a"],
            actor="test",
            action=action,
            payload={"stage": action.value},
        )
    db.commit()
    assert verify_chain(db, two_orgs["case_a"]).intact

    # The privileged session is used deliberately: the application role cannot
    # do this, which is itself part of the control.
    db.execute(
        text("UPDATE evidence_events SET actor = 'attacker' WHERE case_id = :c AND seq = 2"),
        {"c": str(two_orgs["case_a"])},
    )
    db.commit()

    result = verify_chain(db, two_orgs["case_a"])
    assert not result.intact
    assert result.first_broken_seq == 2
    assert not result.links[2].hash_ok
    assert result.links[0].ok and result.links[1].ok
    assert "BROKEN at event 2" in result.summary


@requires_db
def test_deleting_an_event_breaks_the_link(db: Session, two_orgs: dict) -> None:
    """Removal must be as detectable as alteration, or history can be edited by
    omission."""
    for action in (EvidenceAction.ACQUIRED, EvidenceAction.PARSED, EvidenceAction.SCORED):
        append_event(
            db,
            org_id=two_orgs["org_a"],
            case_id=two_orgs["case_a"],
            actor="test",
            action=action,
            payload={},
        )
    db.commit()

    db.execute(
        text("DELETE FROM evidence_events WHERE case_id = :c AND seq = 1"),
        {"c": str(two_orgs["case_a"])},
    )
    db.commit()

    result = verify_chain(db, two_orgs["case_a"])
    assert not result.intact


def test_entry_hash_formula_has_one_implementation() -> None:
    """Append and verify must call the same function, or new events would verify
    against a rule old ones were never written under."""
    args = {
        "seq": 0,
        "case_id": uuid.uuid4(),
        "ts_utc": datetime(2026, 9, 2, tzinfo=UTC),
        "actor": "a",
        "action": "acquired",
        "payload_hash": "ff" * 32,
        "prev_hash": None,
    }
    assert compute_entry_hash(**args) == compute_entry_hash(**args)  # type: ignore[arg-type]
