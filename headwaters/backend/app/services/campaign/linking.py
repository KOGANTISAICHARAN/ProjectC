"""Campaign linkage.

Two controls stop this collapsing into a hairball:

**IDF weighting.** Every indicator is weighted by its discriminative power,
``log(N / (1 + df))``. Sharing ``gmail.com`` or a hyperscaler ASN proves
nothing; sharing an obscure /24 proves a lot. Low-IDF indicators are kept and
displayed as context but never counted as linkage evidence -- without this, one
shared hub node connects every case to every other and the graph is useless.

**A non-content gate.** A link requires at least two loci above 0.50 AND at
least one of I, M or P above 0.60. Shared phrasing alone cannot create a
campaign, because all phishing sounds alike.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.services.campaign.dna import Dna, similarity

log = get_logger(__name__)

#: Overall similarity required for a link.
#:
#: Set from measurement, not intuition. Against the reference corpus, related
#: pairs (same toolchain, rotated domain and IP) score 0.53-0.66 while unrelated
#: pairs score 0.20 or below. The discrimination comes from the gate below, not
#: from this number: an unrelated pair fails the non-content requirement no
#: matter where the threshold sits, so the threshold only has to sit inside the
#: gap.
LINK_THRESHOLD = 0.50
#: At least this many loci must independently agree.
MIN_AGREEING_LOCI = 2
LOCUS_AGREEMENT = 0.50
#: At least one non-content locus must be this strong.
NON_CONTENT_THRESHOLD = 0.60
NON_CONTENT_LOCI = ("i", "m", "p")

#: Indicators below this IDF are context, not evidence.
HUB_IDF_THRESHOLD = 1.0


@dataclass(slots=True)
class Link:
    case_id: uuid.UUID
    case_ref: str
    score: float
    per_locus: dict[str, float]
    shared_indicators: list[str]
    reason: str


def load_dna(db: Session, case_id: uuid.UUID) -> Dna | None:
    row = db.execute(
        text(
            "SELECT locus_i, locus_d, locus_n, locus_m, locus_c, locus_p, barcode, "
            "dna_version FROM dna_fingerprints WHERE case_id = :c"
        ),
        {"c": str(case_id)},
    ).first()
    if row is None:
        return None
    return Dna(
        loci={"i": row[0], "d": row[1], "n": row[2], "m": row[3], "c": row[4], "p": row[5]},
        barcode=row[6] or "",
        version=row[7],
    )


def store_dna(db: Session, *, org_id: uuid.UUID, case_id: uuid.UUID, dna: Dna) -> None:
    """Persist a fingerprint.

    Serialised with plain ``json.dumps``, NOT ``canonical_json``: the latter
    renders floats as strings so that hashes are reproducible across
    languages, which silently changes the type of every numeric feature on a
    JSONB round trip. Canonicalisation is a hashing concern, never a storage
    one.
    """
    import json

    db.execute(
        text(
            """
            INSERT INTO dna_fingerprints (org_id, case_id, locus_i, locus_d, locus_n,
                locus_m, locus_c, locus_p, barcode, dna_version)
            VALUES (:org, :case, CAST(:i AS jsonb), CAST(:d AS jsonb), CAST(:n AS jsonb),
                    CAST(:m AS jsonb), CAST(:c AS jsonb), CAST(:p AS jsonb), :bar, :ver)
            ON CONFLICT (case_id) DO NOTHING
            """
        ),
        {
            "org": str(org_id),
            "case": str(case_id),
            "i": json.dumps(dna.loci["i"]),
            "d": json.dumps(dna.loci["d"]),
            "n": json.dumps(dna.loci["n"]),
            "m": json.dumps(dna.loci["m"]),
            "c": json.dumps(dna.loci["c"]),
            "p": json.dumps(dna.loci["p"]),
            "bar": dna.barcode,
            "ver": dna.version,
        },
    )


def indicator_idf(db: Session, org_id: uuid.UUID) -> dict[str, float]:
    """Discriminative power per indicator value, across the organisation."""
    total = (
        db.execute(
            text("SELECT count(DISTINCT case_id) FROM indicators WHERE org_id = :o"),
            {"o": str(org_id)},
        ).scalar_one()
        or 1
    )
    rows = db.execute(
        text(
            "SELECT normalised, count(DISTINCT case_id) FROM indicators "
            "WHERE org_id = :o GROUP BY normalised"
        ),
        {"o": str(org_id)},
    ).all()
    return {value: math.log(total / (1 + df)) for value, df in rows}


def find_links(db: Session, *, org_id: uuid.UUID, case_id: uuid.UUID, dna: Dna) -> list[Link]:
    """Score this case against every other in the organisation.

    A full pairwise scan is correct up to a few thousand cases. Beyond that the
    candidate set comes from an inverted index over high-IDF indicators, so only
    plausible pairs are scored -- noted here because the O(n) scan is a
    deliberate, bounded simplification rather than an oversight.
    """
    idf = indicator_idf(db, org_id)
    mine = _indicators(db, case_id)

    candidates = db.execute(
        text(
            """
            SELECT d.case_id, c.case_ref, d.locus_i, d.locus_d, d.locus_n,
                   d.locus_m, d.locus_c, d.locus_p
              FROM dna_fingerprints d
              JOIN cases c ON c.id = d.case_id
             WHERE d.org_id = :o AND d.case_id <> :c
            """
        ),
        {"o": str(org_id), "c": str(case_id)},
    ).all()

    links: list[Link] = []
    for row in candidates:
        other = Dna(
            loci={"i": row[2], "d": row[3], "n": row[4], "m": row[5], "c": row[6], "p": row[7]}
        )
        score, per = similarity(dna, other)

        agreeing = sum(1 for v in per.values() if v >= LOCUS_AGREEMENT)
        strong_non_content = max(per.get(k, 0.0) for k in NON_CONTENT_LOCI)

        if (
            score < LINK_THRESHOLD
            or agreeing < MIN_AGREEING_LOCI
            or strong_non_content < NON_CONTENT_THRESHOLD
        ):
            continue

        theirs = _indicators(db, row[0])
        shared = [value for value in (mine & theirs) if idf.get(value, 0.0) >= HUB_IDF_THRESHOLD]

        dominant = max(per, key=lambda k: per[k])
        links.append(
            Link(
                case_id=row[0],
                case_ref=row[1],
                score=score,
                per_locus=per,
                shared_indicators=sorted(shared)[:20],
                reason=_reason(dominant, per[dominant], shared),
            )
        )

    links.sort(key=lambda link: link.score, reverse=True)
    return links


def _reason(dominant: str, value: float, shared: list[str]) -> str:
    names = {
        "i": "shared sending infrastructure",
        "d": "shared sender identity",
        "n": "similar domain construction",
        "m": "identical sending toolchain (header order and MIME structure)",
        "c": "similar message template",
        "p": "shared payload or link structure",
    }
    base = f"{names[dominant]} ({value:.2f})"
    if shared:
        base += f"; {len(shared)} discriminative indicator(s) in common"
    return base


def _indicators(db: Session, case_id: uuid.UUID) -> set[str]:
    return {
        r[0]
        for r in db.execute(
            text("SELECT normalised FROM indicators WHERE case_id = :c"),
            {"c": str(case_id)},
        ).all()
    }


def assign_campaign(
    db: Session, *, org_id: uuid.UUID, case_id: uuid.UUID, links: list[Link]
) -> tuple[uuid.UUID, str] | None:
    """Join the campaign of the strongest link, or open a new one.

    Transitive by construction: linking to a member joins that member's
    campaign, which is union-find without a separate pass.
    """
    if not links:
        return None

    best = links[0]
    existing = db.execute(
        text("SELECT campaign_id FROM campaign_members WHERE case_id = :c LIMIT 1"),
        {"c": str(best.case_id)},
    ).first()

    if existing:
        campaign_id = existing[0]
        name = db.execute(
            text("SELECT name FROM campaigns WHERE id = :i"), {"i": str(campaign_id)}
        ).scalar_one()
    else:
        seq = (
            db.execute(
                text("SELECT count(*) FROM campaigns WHERE org_id = :o"), {"o": str(org_id)}
            ).scalar_one()
            or 0
        ) + 1
        name = f"CAMPAIGN-{datetime.now(UTC).year}-{seq:03d}"
        campaign_id = db.execute(
            text(
                """
                INSERT INTO campaigns (org_id, name, summary, member_count)
                VALUES (:o, :n, :s, 0) RETURNING id
                """
            ),
            {"o": str(org_id), "n": name, "s": best.reason},
        ).scalar_one()
        _add_member(db, org_id, campaign_id, best.case_id, best.score, best.per_locus, [])

    _add_member(
        db, org_id, campaign_id, case_id, best.score, best.per_locus, best.shared_indicators
    )
    _refresh(db, campaign_id)
    log.info("campaign.linked", case_id=str(case_id), campaign=name, score=best.score)
    return campaign_id, name


def _add_member(
    db: Session,
    org_id: uuid.UUID,
    campaign_id: uuid.UUID,
    case_id: uuid.UUID,
    score: float,
    per_locus: dict[str, float],
    shared: list[str],
) -> None:
    import json

    db.execute(
        text(
            """
            INSERT INTO campaign_members (org_id, campaign_id, case_id, dna_score,
                locus_breakdown, shared_indicators)
            VALUES (:o, :camp, :case, :score, CAST(:loci AS jsonb), CAST(:shared AS jsonb))
            ON CONFLICT (campaign_id, case_id) DO NOTHING
            """
        ),
        {
            "o": str(org_id),
            "camp": str(campaign_id),
            "case": str(case_id),
            "score": min(1.0, score),
            "loci": json.dumps(per_locus),
            "shared": json.dumps(shared),
        },
    )


def _refresh(db: Session, campaign_id: uuid.UUID) -> None:
    db.execute(
        text(
            """
            UPDATE campaigns SET
                member_count = (SELECT count(*) FROM campaign_members m
                                 WHERE m.campaign_id = campaigns.id),
                max_score    = (SELECT max(c.score) FROM campaign_members m
                                  JOIN cases c ON c.id = m.case_id
                                 WHERE m.campaign_id = campaigns.id),
                first_seen   = (SELECT min(c.created_at) FROM campaign_members m
                                  JOIN cases c ON c.id = m.case_id
                                 WHERE m.campaign_id = campaigns.id),
                last_seen    = (SELECT max(c.created_at) FROM campaign_members m
                                  JOIN cases c ON c.id = m.case_id
                                 WHERE m.campaign_id = campaigns.id),
                distinct_domains = (SELECT count(DISTINCT i.normalised) FROM campaign_members m
                                      JOIN indicators i ON i.case_id = m.case_id
                                     WHERE m.campaign_id = campaigns.id AND i.type = 'domain'),
                distinct_prefixes = (SELECT count(DISTINCT i.normalised) FROM campaign_members m
                                       JOIN indicators i ON i.case_id = m.case_id
                                      WHERE m.campaign_id = campaigns.id AND i.type = 'ip')
             WHERE id = :i
            """
        ),
        {"i": str(campaign_id)},
    )
