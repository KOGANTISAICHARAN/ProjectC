"""Tenancy: organisations, users, and the membership that joins them."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import MembershipRole
from app.models.mixins import Timestamped, UUIDPrimaryKey, enum_check, enum_column


class Org(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "orgs"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    #: Raw email is deleted after this many days; hashes, indicators, findings
    #: and DNA are retained. Content expires, intelligence persists -- which is
    #: what makes a real deletion request answerable without destroying the
    #: campaign graph built from it.
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, server_default="90")

    #: Per-org configuration: trusted provider overrides, protected identities,
    #: scoring weight overrides. Schema-on-read by design; validated by Pydantic
    #: at the point of use rather than by a migration.
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="org", cascade="all, delete-orphan"
    )


class User(Timestamped, Base):
    """An analyst.

    ``id`` is NOT generated here: it is the subject claim from the Supabase JWT
    (``auth.uid()``). Generating our own would create two identities for one
    person and break every RLS policy.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column(String(200))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    memberships: Mapped[list[Membership]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Membership(Base):
    """Which analysts may see which organisation's cases.

    This table is the sole authority for tenancy. Every RLS policy in the system
    reduces to a lookup against it, so it is deliberately tiny and has no
    soft-delete: revoking access is a DELETE, and takes effect immediately.
    """

    __tablename__ = "memberships"
    # No explicit UniqueConstraint: (org_id, user_id) is already the composite
    # PRIMARY KEY, which enforces the same thing with one index instead of two.
    #
    # `role` drives authorization, so it is constrained in the database as well
    # as in the application: a bad value here is a privilege question.
    __table_args__ = (enum_check("role", MembershipRole, "role_vocab"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[MembershipRole] = mapped_column(
        enum_column(MembershipRole), nullable=False, server_default=MembershipRole.ANALYST.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    org: Mapped[Org] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")
