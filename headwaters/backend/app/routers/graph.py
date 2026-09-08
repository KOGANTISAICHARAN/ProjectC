"""Graph and timeline projections of a case."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.security.deps import get_tenant_db
from app.security.identity import resolve_user_id

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["graph"])


def tenant_session(user_id: Annotated[uuid.UUID, Depends(resolve_user_id)]) -> Any:
    yield from get_tenant_db(user_id)


TenantDb = Annotated[Session, Depends(tenant_session)]

#: Indicator values that connect everything to everything. Rendered as context,
#: never as linkage evidence -- without suppression the graph collapses into a
#: single hairball centred on whichever hub is most common.
HUB_VALUES = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "google.com",
    "microsoft.com",
    "bit.ly",
    "t.co",
}


@router.get("/cases/{case_id}/graph")
def get_graph(case_id: uuid.UUID, db: TenantDb, depth: int = 2) -> dict[str, Any]:
    """Cytoscape-format graph of this case and everything it shares with others.

    Emitted in Cytoscape's ``{data: {...}}`` element shape so the current
    deterministic SVG renderer and a future Cytoscape/React Flow renderer consume
    exactly the same payload.
    """
    case = db.execute(
        text("SELECT case_ref, score, band FROM cases WHERE id = :id"), {"id": str(case_id)}
    ).first()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add_node(node_id: str, label: str, kind: str, **extra: Any) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"data": {"id": node_id, "label": label, "kind": kind, **extra}}

    root = f"case:{case_id}"
    add_node(root, case[0], "case", score=case[1], band=case[2], root=True)

    indicators = db.execute(
        text(
            "SELECT type, normalised, value FROM indicators WHERE case_id = :id "
            "ORDER BY type, normalised"
        ),
        {"id": str(case_id)},
    ).all()

    for kind, normalised, value in indicators:
        node_id = f"{kind}:{normalised}"
        add_node(
            node_id,
            value[:60],
            kind,
            hub=normalised in HUB_VALUES,
        )
        edges.append({"data": {"source": root, "target": node_id, "type": "contains"}})

    if depth >= 2:
        # Second hop: other cases that share a non-hub indicator. The hub filter
        # is what keeps this a graph rather than a hairball.
        shared = db.execute(
            text(
                """
                SELECT DISTINCT i2.type, i2.normalised, c2.id, c2.case_ref, c2.score, c2.band
                  FROM indicators i1
                  JOIN indicators i2
                    ON i2.normalised = i1.normalised AND i2.case_id <> i1.case_id
                  JOIN cases c2 ON c2.id = i2.case_id
                 WHERE i1.case_id = :id
                """
            ),
            {"id": str(case_id)},
        ).all()

        for kind, normalised, other_id, other_ref, score, band in shared:
            if normalised in HUB_VALUES:
                continue
            other = f"case:{other_id}"
            add_node(other, other_ref, "case", score=score, band=band)
            edges.append(
                {"data": {"source": other, "target": f"{kind}:{normalised}", "type": "shares"}}
            )

    campaign = db.execute(
        text(
            "SELECT c.id, c.name, c.member_count FROM campaigns c "
            "JOIN campaign_members m ON m.campaign_id = c.id WHERE m.case_id = :id"
        ),
        {"id": str(case_id)},
    ).first()
    if campaign:
        node_id = f"campaign:{campaign[0]}"
        add_node(node_id, campaign[1], "campaign", members=campaign[2])
        members = db.execute(
            text(
                "SELECT cs.id, cs.case_ref, cs.score, cs.band, m.dna_score "
                "FROM campaign_members m JOIN cases cs ON cs.id = m.case_id "
                "WHERE m.campaign_id = :cid"
            ),
            {"cid": str(campaign[0])},
        ).all()
        for member_id, ref, score, band, dna in members:
            member_node = f"case:{member_id}"
            add_node(member_node, ref, "case", score=score, band=band)
            edges.append(
                {
                    "data": {
                        "source": member_node,
                        "target": node_id,
                        "type": "member_of",
                        "weight": float(dna),
                    }
                }
            )

    return {
        "elements": {"nodes": list(nodes.values()), "edges": edges},
        "hub_values_suppressed": sorted(HUB_VALUES),
        "note": (
            "Edges indicate shared indicators or shared tooling. They are a linkage "
            "hypothesis, not attribution."
        ),
    }


@router.get("/cases/{case_id}/timeline")
def get_timeline(case_id: uuid.UUID, db: TenantDb) -> dict[str, Any]:
    """Chronological reconstruction: the message's own journey, then the analysis.

    Two kinds of entry with different epistemic status, and they are labelled so
    a reader can tell them apart. ``asserted`` entries come from headers the
    sender wrote; ``observed`` and ``analysis`` entries are our own records.
    """
    entries: list[dict[str, Any]] = []

    hops = db.execute(
        text(
            "SELECT seq, hop_ts_utc, observed_ip, by_host, trust_state, asn_org "
            "FROM received_hops WHERE case_id = :id AND hop_ts_utc IS NOT NULL "
            "ORDER BY hop_ts_utc"
        ),
        {"id": str(case_id)},
    ).all()
    for seq, ts, ip, by_host, trust, org in hops:
        vouched = trust in ("vouched", "boundary")
        entries.append(
            {
                "at": ts.isoformat(),
                "kind": "observed" if vouched else "asserted",
                "title": f"Hop {seq}: handled by {by_host or 'unknown host'}",
                "detail": f"peer {ip or 'not recorded'}" + (f" · {org}" if org else ""),
                "trust": trust,
            }
        )

    events = db.execute(
        text(
            "SELECT seq, ts_utc, actor, action FROM evidence_events "
            "WHERE case_id = :id ORDER BY seq"
        ),
        {"id": str(case_id)},
    ).all()
    for seq, ts, actor, action in events:
        entries.append(
            {
                "at": ts.isoformat(),
                "kind": "analysis",
                "title": action.replace("_", " "),
                "detail": actor,
                "trust": "recorded",
                "seq": seq,
            }
        )

    entries.sort(key=lambda e: e["at"])
    return {
        "entries": entries,
        "legend": {
            "asserted": "Timestamp written by the sender. Retained, never trusted.",
            "observed": "Recorded by infrastructure this system recognises.",
            "analysis": "This platform's own actions, hash-chained.",
        },
    }
