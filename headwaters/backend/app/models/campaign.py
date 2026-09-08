"""Campaign correlation: fingerprints, the indicator graph, and clusters.

Correlation, never attribution. A DNA match indicates shared tooling,
infrastructure or template lineage -- it can equally mean one actor, one
purchased phishing kit, or one phishing-as-a-service platform used by fifty
unrelated actors. See docs/CLAIM_CONTRACT.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import EdgeType, NodeType
from app.models.mixins import CreatedAt, OrgScoped, Timestamped, UUIDPrimaryKey, enum_column


class DnaFingerprint(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """Email DNA: six loci, stored separately rather than as one blob.

    Separating them is the whole point. Attackers cheaply rotate domains (locus
    D/N), IP addresses (locus I) and wording (locus C). What they rarely change
    is their sending software -- header emission order, MIME part tree, boundary
    format -- which is locus M. Keeping the loci apart lets a match survive the
    three things that actually change between waves.
    """

    __tablename__ = "dna_fingerprints"
    __table_args__ = (UniqueConstraint("case_id", name="uq_dna_fingerprints_case_id"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )

    locus_i: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # infra
    locus_d: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # identity
    locus_n: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # naming
    locus_m: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # tooling
    locus_c: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # content
    locus_p: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # payload

    #: Six segmented bands rendered in the UI. Two cases stacked with matching
    #: cells lit makes linkage legible without reading a number.
    barcode: Mapped[str | None] = mapped_column(String(256))

    #: Which loci algorithm produced this. Fingerprints from different versions
    #: are not comparable, so similarity queries filter on it.
    dna_version: Mapped[str] = mapped_column(String(16), nullable=False, server_default="v1")


class GraphNode(OrgScoped, UUIDPrimaryKey, Base):
    """A vertex in the org's intelligence graph.

    Nodes are deduplicated per org by (type, value): the same IP seen in twenty
    cases is one node with twenty edges, which is what makes the pivot useful.
    """

    __tablename__ = "graph_nodes"
    __table_args__ = (
        UniqueConstraint("org_id", "type", "value", name="uq_graph_nodes_org_type_value"),
        Index("ix_graph_nodes_org_type", "org_id", "type"),
    )

    type: Mapped[NodeType] = mapped_column(enum_column(NodeType), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    label: Mapped[str | None] = mapped_column(String(300))

    idf: Mapped[float | None] = mapped_column(Numeric(6, 3))

    #: Hub nodes (gmail.com, AS15169, bit.ly) connect everything to everything.
    #: They are rendered as context and excluded from linkage evidence -- without
    #: this the campaign graph collapses into a single useless hairball.
    is_hub: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")


class GraphEdge(OrgScoped, UUIDPrimaryKey, Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("org_id", "src_id", "dst_id", "type", name="uq_graph_edges_triple"),
        Index("ix_graph_edges_src", "org_id", "src_id"),
        Index("ix_graph_edges_dst", "org_id", "dst_id"),
    )

    src_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    dst_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    type: Mapped[EdgeType] = mapped_column(enum_column(EdgeType), nullable=False)
    weight: Mapped[float] = mapped_column(Numeric(6, 3), nullable=False, server_default="1.0")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: Which case or provider asserted this edge, for provenance.
    source: Mapped[str | None] = mapped_column(String(128))


class Campaign(OrgScoped, UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "campaigns"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_campaigns_org_id_name"),
        CheckConstraint("member_count >= 0", name="member_count_non_negative"),
    )

    name: Mapped[str] = mapped_column(String(64), nullable=False)  # CAMPAIGN-2026-0003
    alias: Mapped[str | None] = mapped_column(String(64))  # SPINDRIFT-03
    summary: Mapped[str | None] = mapped_column(Text)

    member_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_score: Mapped[int | None] = mapped_column(SmallInteger)

    distinct_domains: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    distinct_prefixes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    distinct_asns: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")


class CampaignMember(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """Join table with the *reason* attached.

    A campaign edge that cannot explain itself is not intelligence. Every
    membership carries the similarity score, the per-locus breakdown and the
    specific high-IDF indicators that justified the link.
    """

    __tablename__ = "campaign_members"
    __table_args__ = (
        UniqueConstraint("campaign_id", "case_id", name="uq_campaign_members_campaign_case"),
        CheckConstraint("dna_score >= 0 AND dna_score <= 1", name="dna_score_range"),
    )

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    dna_score: Mapped[float] = mapped_column(Numeric(4, 3), nullable=False)
    locus_breakdown: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )
    shared_indicators: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")
