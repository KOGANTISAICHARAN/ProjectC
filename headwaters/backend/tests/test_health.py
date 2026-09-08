"""Phase 0 acceptance tests: the service boots, is observable, and is hardened."""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from tests.conftest import ALLOWED_ORIGIN, UNLISTED_ORIGIN


def test_healthz_is_alive_without_touching_dependencies(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "headwaters-api"


def test_every_response_carries_a_request_id(client: TestClient) -> None:
    r = client.get("/healthz")
    assert uuid.UUID(r.headers["X-Request-ID"])


def test_client_supplied_request_id_is_echoed_when_valid(client: TestClient) -> None:
    rid = str(uuid.uuid4())
    r = client.get("/healthz", headers={"X-Request-ID": rid})
    assert r.headers["X-Request-ID"] == rid


def test_malformed_request_id_is_replaced_not_reflected(client: TestClient) -> None:
    """SECURITY: an attacker-supplied header must never land in logs verbatim."""
    r = client.get("/healthz", headers={"X-Request-ID": "not-a-uuid\ninjected"})
    assert r.headers["X-Request-ID"] != "not-a-uuid\ninjected"
    assert uuid.UUID(r.headers["X-Request-ID"])


def test_security_headers_present(client: TestClient) -> None:
    h = client.get("/healthz").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]


def test_cors_allowlist_admits_configured_origin(client: TestClient) -> None:
    r = client.options(
        "/healthz",
        headers={
            "Origin": ALLOWED_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN


def test_cors_rejects_unlisted_origin(client: TestClient) -> None:
    """SECURITY: a wildcard here would let any installed extension call the API."""
    r = client.options(
        "/healthz",
        headers={"Origin": UNLISTED_ORIGIN, "Access-Control-Request-Method": "GET"},
    )
    assert r.headers.get("access-control-allow-origin") != UNLISTED_ORIGIN


def test_readyz_reports_dependency_state(client: TestClient) -> None:
    """Readiness returns 200 or 503 depending on the database -- never 500."""
    r = client.get("/readyz")
    assert r.status_code in (200, 503)
    assert "database" in r.json()["checks"]


def test_blank_secret_env_var_is_treated_as_unset() -> None:
    """A blank `OPENAI_API_KEY=` in .env must read as "not configured".

    Regression: an empty string is not None, so the service reported the
    credential as present and would have failed later with an opaque auth error
    rather than a clear signal at startup.
    """
    from app.core.config import get_settings

    settings = get_settings()
    # conftest sets both to "" -- the coercion must report them as absent.
    assert settings.openai_api_key is None
    assert settings.sentry_dsn is None
