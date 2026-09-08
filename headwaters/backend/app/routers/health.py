"""Liveness and readiness endpoints.

``/healthz`` answers "is this process alive" and must not touch dependencies --
if it did, a database blip would cause the orchestrator to kill healthy
containers. ``/readyz`` answers "can this process serve traffic" and is what the
deploy gate uses, so a failed migration never takes traffic.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.db.session import check_database, get_app_engine, get_engine

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    environment: str
    version: str


class ReadyResponse(BaseModel):
    status: Literal["ready", "degraded"]
    checks: dict[str, bool]


@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
def healthz() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.service_name,
        environment=settings.environment,
        version="0.1.0",
    )


@router.get("/readyz", response_model=ReadyResponse, summary="Readiness probe")
def readyz(response: Response) -> ReadyResponse:
    # Both connections are probed: the request path is useless without the
    # unprivileged one, and reporting only the system connection would show a
    # healthy service that cannot serve a single authenticated read.
    checks = {
        "database": check_database(get_engine()),
        "database_app": check_database(get_app_engine()),
    }
    ready = all(checks.values())
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadyResponse(status="ready" if ready else "degraded", checks=checks)
