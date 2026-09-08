"""FastAPI application factory.

Middleware order matters and is asserted by the tests: request context is
outermost so that every log line -- including one emitted while CORS rejects a
request -- carries a request id.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.routers import cases, evidence, graph, health, reports

log = get_logger(__name__)


def _init_sentry(settings: Settings) -> None:
    """Initialise error tracking when a DSN is configured.

    Imported lazily so the dependency stays optional: a missing SDK must not
    prevent the service from starting.
    """
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk
    except ModuleNotFoundError:
        log.warning("sentry.sdk_missing")
        return

    def _scrub(event: dict[str, object], _hint: object) -> dict[str, object]:
        # SECURITY: request bodies here are raw email. Never ship them offsite.
        event.pop("request", None)
        return event

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        traces_sample_rate=0.1,
        send_default_pii=False,
        before_send=_scrub,
    )
    log.info("sentry.initialised", environment=settings.environment)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    log.info(
        "app.startup",
        environment=settings.environment,
        ti_mode=settings.ti_mode,
        openai_configured=settings.openai_api_key is not None,
    )

    # Refuse to serve on a connection that can bypass row-level security.
    # There is no safe degraded mode here: the failure is invisible at runtime
    # and its symptom is one customer reading another's correspondence.
    from app.db.guards import assert_privileged, assert_rls_enforced
    from app.db.session import get_app_engine, get_engine

    assert_rls_enforced(get_app_engine(), label="request-path")
    assert_privileged(get_engine(), label="system")

    # Seed the demo tenant so the API is usable immediately. Skipped in
    # production: a hard-coded organisation is a development convenience, not a
    # deployment artefact.
    if not settings.is_production:
        from app.db.session import SessionLocal
        from app.services.demo_seed import seed_demo_tenant

        with SessionLocal() as seed_db:
            seed_demo_tenant(seed_db)

    yield
    log.info("app.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=settings.environment != "local")
    _init_sentry(settings)

    app = FastAPI(
        title="Headwaters API",
        description=(
            "Email threat detection and forensic intelligence. "
            "Deterministic forensics establish fact; the AI layer reads intent only."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    # --- middleware (added last == outermost) -----------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

    # Imported here to keep the module import graph shallow for tooling.
    from app.security.middleware import RequestContextMiddleware, SecurityHeadersMiddleware

    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_production)
    app.add_middleware(RequestContextMiddleware)

    # --- routers -----------------------------------------------------------
    app.include_router(health.router)
    app.include_router(cases.router)
    app.include_router(evidence.router)
    app.include_router(reports.router)
    app.include_router(graph.router)

    # --- errors ------------------------------------------------------------
    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        """RFC 9457 problem detail.

        SECURITY: the response never contains exception text. Correlate with the
        stack trace using the request id, which is safe to expose.
        """
        request_id = getattr(request.state, "request_id", None)
        log.exception("http.unhandled", path=request.url.path)
        return JSONResponse(
            status_code=500,
            media_type="application/problem+json",
            content={
                "type": "about:blank",
                "title": "Internal Server Error",
                "status": 500,
                "request_id": request_id,
            },
        )

    return app


app = create_app()
