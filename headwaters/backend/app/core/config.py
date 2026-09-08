"""Application configuration.

Settings are read from the environment (and a local ``.env`` during development).
Nothing here has a production-safe default that could silently mask a missing
secret: ``DATABASE_URL`` is required, and the OpenAI/Supabase values default to
``None`` so that a feature which needs them fails loudly rather than quietly
degrading into an unconfigured state.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "staging", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- runtime -----------------------------------------------------------
    environment: Environment = "local"
    log_level: str = "INFO"
    service_name: str = "headwaters-api"

    # --- persistence -------------------------------------------------------
    #: The PRIVILEGED connection: migrations, the bootstrap step, and the worker.
    #: Bypasses row-level security by design -- a worker is a system actor that
    #: must process every organisation's jobs.
    database_url: str

    #: The UNPRIVILEGED connection used for everything done on behalf of a user.
    #: Must authenticate as a role that is neither a superuser nor holds
    #: BYPASSRLS, or every tenancy policy silently stops applying. Verified at
    #: startup by app.db.guards.assert_rls_enforced().
    database_url_app: str | None = None

    #: Password granted to the application role by the bootstrap step. Never
    #: appears in a migration: credentials do not belong in version control.
    app_db_password: str | None = None

    # --- HTTP --------------------------------------------------------------
    # Stored as a raw string because pydantic-settings attempts JSON decoding
    # for list-typed fields, which makes the natural "a,b,c" env format fail.
    allowed_origins_raw: str = Field(default="http://localhost:3000", alias="ALLOWED_ORIGINS")

    # SECURITY: enforced by the edge before the request body is buffered, so a
    # 500 MB upload costs us a rejected connection rather than 500 MB of RSS.
    max_upload_bytes: int = 26_214_400  # 25 MiB

    # --- OpenAI (Phase 7) --------------------------------------------------
    # Model identifiers are configuration, never constants: they are recorded
    # per case in the evidence chain, so changing one must be a deployment
    # event that is visible in the audit trail.
    openai_api_key: str | None = None
    openai_model_extract: str = "gpt-4o-mini"
    openai_model_narrative: str = "gpt-4.1"
    prompt_version: str = "v1"

    # --- Supabase (Phase 2 / 9) -------------------------------------------
    supabase_url: str | None = None
    supabase_jwks_url: str | None = None
    supabase_service_role_key: str | None = None

    # --- evidence (Phase 8) -----------------------------------------------
    evidence_signing_key: str | None = None

    # --- threat intelligence (Phase 6) ------------------------------------
    ti_mode: Literal["cached", "live", "offline"] = "cached"

    # --- observability -----------------------------------------------------
    sentry_dsn: str | None = None

    @field_validator(
        "database_url_app",
        "app_db_password",
        "openai_api_key",
        "supabase_url",
        "supabase_jwks_url",
        "supabase_service_role_key",
        "evidence_signing_key",
        "sentry_dsn",
        mode="before",
    )
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        """Treat an empty environment variable as absent.

        ``OPENAI_API_KEY=`` in a .env file yields the empty string, not None.
        Without this, the service reports a credential as configured and then
        fails at call time with an opaque auth error instead of a clear
        "not configured" at startup.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def allowed_origins(self) -> list[str]:
        """CORS allowlist.

        SECURITY: deliberately explicit. A wildcard here would let any origin --
        including any other extension installed in the analyst's browser -- call
        this API with the analyst's bearer token.
        """
        return [o.strip() for o in self.allowed_origins_raw.split(",") if o.strip()]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_database_url_app(self) -> str:
        """The connection the request path must use.

        Outside production this falls back to ``database_url`` so a fresh
        checkout still boots -- but the startup guard then refuses to serve,
        which is the intended outcome: a loud, immediate failure that names the
        fix, rather than a service that runs with tenancy quietly disabled.
        """
        return self.database_url_app or self.database_url

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor. Import this, not a module-level instance, so
    tests can clear the cache and substitute an environment."""
    return Settings()
