"""Caller identity.

Phase 8 replaces this with Supabase JWT verification against the project JWKS.
Until then a demo identity is resolved so the rest of the stack -- including the
RLS path -- can be exercised end to end.

This is a stub for AUTHENTICATION only. It is deliberately not a stub for
AUTHORIZATION: the resolved user is bound to the session via ``tenant_scope``,
so every query still runs under row-level security as that user. Wiring real
token verification changes where the id comes from, and nothing else.

It refuses to operate in production.
"""

from __future__ import annotations

import uuid

from fastapi import Header, HTTPException, status

from app.core.config import get_settings

#: Stable ids for the seeded demo tenant, so a restart does not orphan cases.
DEMO_ORG_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")
DEMO_USER_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")
DEMO_ORG_SLUG = "kaveri-financial"
DEMO_USER_EMAIL = "p.menon@kaverifs.com"


def resolve_user_id(x_headwaters_user: str | None = Header(default=None)) -> uuid.UUID:
    """Resolve the calling analyst.

    Outside production, falls back to the seeded demo analyst so the API is
    usable before authentication lands. In production this raises rather than
    defaulting: an unauthenticated request must never silently acquire an
    identity, which is precisely how a stub like this becomes a vulnerability.
    """
    settings = get_settings()

    if x_headwaters_user:
        try:
            return uuid.UUID(x_headwaters_user)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="X-Headwaters-User must be a UUID",
            ) from exc

    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return DEMO_USER_ID
