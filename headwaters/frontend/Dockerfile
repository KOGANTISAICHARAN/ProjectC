# syntax=docker/dockerfile:1.9
# Development image. Production is built and served by Vercel; this exists so
# `docker compose up` yields a complete local stack — which is also the demo
# fallback when conference wifi fails.
FROM node:22-bookworm-slim

ENV NODE_ENV=development \
    NEXT_TELEMETRY_DISABLED=1

# Compose mounts anonymous volumes over /srv/.next and /srv/node_modules to stop
# the host bind-mount shadowing them. Docker seeds each volume from the image
# directory at that path and inherits its ownership — so these directories must
# exist and be owned by `node` before we drop privileges, or `next dev` exits
# with EACCES trying to write .next/cache.
RUN mkdir -p /srv/.next /srv/node_modules && chown -R node:node /srv

WORKDIR /srv
USER node

COPY --chown=node:node package.json ./
# Installing as `node` keeps node_modules writable by the runtime user, which
# some Next.js tooling requires for its own caches.
RUN npm install --no-audit --no-fund

COPY --chown=node:node . .

EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--hostname", "0.0.0.0"]
