"""Structured logging.

Every log line is JSON on stdout carrying a ``request_id``, so a Sentry event,
an API response and a container log line correlate on one identifier.

Records emitted by third-party libraries (uvicorn, sqlalchemy, httpx) are routed
through the *same* structlog processor chain via ``ProcessorFormatter``. Without
that bridge those libraries render in stdlib's format while our own code renders
as JSON, and half the production log becomes unparseable.

SECURITY: this module never logs email content, headers, tokens or attachment
bytes. Only identifiers and hashes are safe to emit -- log output is retained
longer, and in more places, than the evidence store.
"""

from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from typing import Any

import structlog

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

#: Libraries whose records we route through structlog. Their own handlers are
#: removed so a message is emitted exactly once.
_BRIDGED_LOGGERS = (
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
    "gunicorn.error",
    "gunicorn.access",
    "sqlalchemy.engine",
    "httpx",
    "httpx2",
    "httpcore",
    "alembic",
)


def set_request_id(value: str | None) -> None:
    _request_id.set(value)


def get_request_id() -> str | None:
    return _request_id.get()


def _inject_request_id(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    rid = _request_id.get()
    if rid is not None:
        event_dict["request_id"] = rid
    return event_dict


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    """Configure structlog and bridge stdlib logging into it.

    Idempotent: calling it twice (app factory plus worker entrypoint, or once
    per test) replaces handlers rather than stacking them, which would otherwise
    duplicate every line.
    """
    numeric = getattr(logging, level.upper(), logging.INFO)

    # Processors shared by both origins. They must run *before* the renderer and
    # must not include the renderer itself, which ProcessorFormatter appends.
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        _inject_request_id,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            # Hands the event dict to ProcessorFormatter instead of rendering
            # here, so structlog and stdlib share one renderer.
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        # Applied only to records originating from stdlib loggers.
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric)

    for name in _BRIDGED_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True

    # SQLAlchemy and httpx are chatty at INFO and would drown real signal.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpx2").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # RequestContextMiddleware emits a richer, request-id-tagged access line
    # for every request. Leaving uvicorn/gunicorn access logs at INFO doubles
    # log volume with a strictly less useful duplicate.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("gunicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.stdlib.get_logger(name)
