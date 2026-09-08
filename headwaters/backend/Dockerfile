# syntax=docker/dockerfile:1.9
# --------------------------------------------------------------------------
# Headwaters backend. One image, two entrypoints (API and worker) — the worker
# runs the same code, so services/ can never drift between them.
# --------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# libmagic is used from Phase 3 onward for content-type sniffing of attachments;
# installing it here keeps the layer stable across phases.
# libmagic: content-type sniffing for attachments.
# The pango/cairo/gdk-pixbuf set: WeasyPrint's rendering backend. WeasyPrint is
# a pure-Python package but binds to these system libraries at import time, so
# `pip install weasyprint` alone yields a package that imports and then fails.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 curl \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 \
        libgdk-pixbuf-2.0-0 libcairo2 libffi8 shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

WORKDIR /srv

# ---- dependency layer (cached independently of source) -------------------
FROM base AS deps
COPY pyproject.toml ./
RUN uv pip install --system --no-cache '.[dev]'

# ---- runtime -------------------------------------------------------------
FROM base AS runtime
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# SECURITY: never run the API as root. An email parser processing hostile input
# is exactly the process you do not want owning the container filesystem.
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin headwaters
COPY --chown=headwaters:headwaters . /srv
USER headwaters

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

# Overridden by docker-compose for local dev (--reload) and by render.yaml for
# the worker (python -m app.workers.runner).
CMD ["gunicorn", "app.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "2", "--bind", "0.0.0.0:8000", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "--timeout", "60", "--graceful-timeout", "30"]
