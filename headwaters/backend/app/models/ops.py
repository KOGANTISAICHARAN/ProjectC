"""Operational tables: the job queue, the LLM cache, the evidence chain, reports."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import EvidenceAction, JobKind, JobState
from app.models.mixins import CreatedAt, OrgScoped, UUIDPrimaryKey, enum_check, enum_column


class Job(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    """Band B work, queued in Postgres rather than a broker.

    ``SELECT ... FOR UPDATE SKIP LOCKED`` over this table is transactional with
    the case row -- a case and its first job are created atomically -- needs no
    additional service, survives worker restarts and is correct under concurrent
    workers. Redis and arq become worth their operational cost at roughly 20
    jobs/second; below that they are two more things to run out of memory.
    """

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        # Queue correctness depends on the state vocabulary: the partial indexes
        # below reference literal state values, so an unexpected one would make
        # a job permanently invisible to the claim query.
        enum_check("state", JobState, "state_vocab"),
        CheckConstraint("max_attempts >= 1", name="max_attempts_positive"),
        # Partial index: the claim query only ever scans queued rows, and this
        # keeps the index small even when the table holds a million done rows.
        Index(
            "ix_jobs_claimable",
            "run_after",
            "created_at",
            postgresql_where=text("state = 'queued'"),
        ),
        Index("ix_jobs_case", "case_id"),
        # One in-flight job of a given kind per case. Prevents a retried request
        # or a duplicated event from enqueueing the same OpenAI call twice.
        Index(
            "uq_jobs_active_kind_per_case",
            "case_id",
            "kind",
            unique=True,
            postgresql_where=text("state IN ('queued', 'running')"),
        ),
    )

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE")
    )
    kind: Mapped[JobKind] = mapped_column(enum_column(JobKind), nullable=False)
    state: Mapped[JobState] = mapped_column(
        enum_column(JobState), nullable=False, server_default=JobState.QUEUED.value
    )

    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="3")

    #: Exponential backoff target. A job is invisible to the claim query until
    #: now() >= run_after.
    run_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Identifies the worker holding the lease, so a crashed worker's jobs can be
    #: reclaimed by the stale-lease sweep rather than being stuck forever.
    locked_by: Mapped[str | None] = mapped_column(String(128))

    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    last_error: Mapped[str | None] = mapped_column(Text)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LlmCache(Base):
    """Deterministic replay for model calls.

    Keyed by ``sha256(model_id || prompt_version || normalised_input)``. A hit
    returns in milliseconds with no network, which is simultaneously the cost
    control, the demo's offline guarantee, and the reason the same email always
    yields the same analysis -- the reproducibility property a forensic pipeline
    requires and a temperature setting alone cannot deliver.

    NOT org-scoped: the key already includes the full input, so a hit is only
    possible for a byte-identical prompt. There is no cross-tenant inference
    here, and sharing the cache is what makes a seeded corpus useful.
    """

    __tablename__ = "llm_cache"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    model_id: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    tokens: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    hits: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EvidenceEvent(OrgScoped, UUIDPrimaryKey, Base):
    """Append-only chain of custody.

    ``entry_hash = SHA256(canonical_json(seq || case_id || ts_utc || actor ||
    action || payload_hash || prev_hash))``. Altering event 4 makes 5, 6 and 7
    fail verification, and the verifier names the exact broken link.

    Append-only is enforced by Postgres, not by convention: UPDATE and DELETE are
    revoked from the application role in the RLS migration. Code that "must not"
    do something eventually does; a revoked grant cannot.

    Canonical JSON means sorted keys, no insignificant whitespace, UTF-8 and a
    fixed number format. Without a canonicalisation rule, verification is not
    reproducible across languages -- which is the difference between a real
    implementation and a demo.
    """

    __tablename__ = "evidence_events"
    __table_args__ = (
        UniqueConstraint("case_id", "seq", name="uq_evidence_events_case_id_seq"),
        CheckConstraint("seq >= 0", name="seq_non_negative"),
        # Audit vocabulary is constrained in the database: chain-of-custody
        # records must not be able to carry an action nobody can interpret.
        enum_check("action", EvidenceAction, "action_vocab"),
        CheckConstraint("char_length(entry_hash) = 64", name="entry_hash_length"),
        Index("ix_evidence_events_case_seq", "case_id", "seq"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    ts_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: A user id, or a service identity such as "worker:ai_extract". Both are
    #: recorded: custody covers humans and pipelines alike.
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[EvidenceAction] = mapped_column(enum_column(EvidenceAction), nullable=False)

    #: Hash of the stage's own output, so the event commits to what happened
    #: without copying it.
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    #: Reproducibility payload: weights version, model id, prompt version,
    #: dataset versions. What lets a third party re-derive this result.
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default="{}"
    )

    #: NULL only for seq 0, the acquisition event.
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    #: Ed25519 over entry_hash. Integrity says the log was not altered; a
    #: signature says *this analyser* produced it. Non-repudiation is what an
    #: auditor actually asks for.
    signature: Mapped[str | None] = mapped_column(Text)
    signing_key_id: Mapped[str | None] = mapped_column(String(64))


class Report(OrgScoped, UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("case_id", "version", name="uq_reports_case_id_version"),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    storage_key: Mapped[str | None] = mapped_column(String(512))
    pdf_sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)

    #: Redacted reports mask recipient PII while the hashes remain over the
    #: unredacted original, accompanied by a manifest so the redaction itself is
    #: auditable.
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    redaction_manifest: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )

    #: Section 63 Bharatiya Sakshya Adhiniyam 2023 certificate (successor to
    #: s.65B of the Evidence Act), generated as a report appendix.
    includes_s63_cert: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    merkle_root: Mapped[str | None] = mapped_column(String(64))
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False, server_default="pending")
    page_count: Mapped[int | None] = mapped_column(SmallInteger)
