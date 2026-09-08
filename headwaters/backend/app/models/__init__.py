"""ORM models.

Every model is imported here so ``Base.metadata`` is fully populated before
Alembic autogenerates a migration. A model that is not imported is silently
absent from the diff, which produces a migration that appears to succeed and
then fails at runtime.
"""

from __future__ import annotations

from app.models.campaign import (
    Campaign,
    CampaignMember,
    DnaFingerprint,
    GraphEdge,
    GraphNode,
)
from app.models.case import (
    AiAnalysis,
    AuthResultRow,
    Case,
    EmailArtifact,
    EmailHeader,
    Finding,
    Indicator,
    OriginAssessment,
    ReceivedHop,
)
from app.models.ops import EvidenceEvent, Job, LlmCache, Report
from app.models.org import Membership, Org, User

__all__ = [
    "AiAnalysis",
    "AuthResultRow",
    "Campaign",
    "CampaignMember",
    "Case",
    "DnaFingerprint",
    "EmailArtifact",
    "EmailHeader",
    "EvidenceEvent",
    "Finding",
    "GraphEdge",
    "GraphNode",
    "Indicator",
    "Job",
    "LlmCache",
    "Membership",
    "Org",
    "OriginAssessment",
    "ReceivedHop",
    "Report",
    "User",
]

#: Tables holding customer data. The RLS migration iterates this list, so adding
#: a tenant table without adding it here is a tenancy bug -- a test asserts the
#: two stay in sync.
TENANT_TABLES: tuple[str, ...] = (
    "cases",
    "email_artifacts",
    "email_headers",
    "received_hops",
    "auth_results",
    "origin_assessment",
    "indicators",
    "findings",
    "ai_analysis",
    "dna_fingerprints",
    "graph_nodes",
    "graph_edges",
    "campaigns",
    "campaign_members",
    "jobs",
    "evidence_events",
    "reports",
)
