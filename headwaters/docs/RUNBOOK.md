# Runbook

## Local stack will not start

| Symptom | Cause | Fix |
|---|---|---|
| `api` exits immediately | `DATABASE_URL` unset or unreachable | `make init`, then `make up`. Confirm `db` is healthy: `docker compose ps` |
| `readyz` returns 503 with `database: false` | Postgres still starting, or migrations not run | Wait for the healthcheck; from Phase 2, `make migrate` |
| `web` shows "API unreachable" | `api` not up, or `API_BASE_URL` wrong | Inside compose it must be `http://api:8000`, not `localhost` |
| Next.js crashes on module resolution | Bind mount shadowed `node_modules` | `make clean && make up` — the anonymous volume is recreated |
| Port already allocated | Something else on the host port | `make ports`, then set `WEB_PORT`/`API_PORT` |
| Dashboard shows **someone else's app**, no error anywhere | On macOS a process bound to `[::1]:<port>` beats Docker's wildcard bind, and `localhost` resolves to IPv6 first. Docker reports the container as running and healthy | Use `127.0.0.1:<port>` (IPv4) to reach the container, and `make ports` / `lsof -nP -iTCP:<port> -sTCP:LISTEN` to find the squatter. Defaults moved to 3100 for this reason |
| `web` exits: `EACCES ... /srv/.next/cache` | An anonymous volume was seeded from an image directory owned by root, so the unprivileged runtime user cannot write | Fixed in `frontend/Dockerfile`: the mount points are created and chowned to `node` *before* `USER node`. If it recurs after editing that file, `make clean` to drop the stale volumes |
| `db` logs `password authentication failed for user "postgres"` | **Not our stack** — nothing here uses that role; our only credentials are `headwaters`/`headwaters`. Something on the host was dialling the published port | Postgres is no longer published to the host. To find the culprit if you re-publish it: `lsof -nP -iTCP:5432` |

## Verifying a deploy

```bash
curl -fsS https://<api-host>/healthz    # process alive
curl -fsS https://<api-host>/readyz     # dependencies reachable
```

`/readyz` is the deploy gate: a failed migration must never take traffic.

## Key rotation

Written now, before it is needed at 2am.

- **`OPENAI_API_KEY`** — revoke in the OpenAI dashboard, issue a new key, update
  the Render environment group, redeploy. No data migration; cached LLM results
  remain valid because the cache key includes the *model* and *prompt version*,
  not the credential.
- **`EVIDENCE_SIGNING_KEY`** (Phase 8) — generate a new Ed25519 pair and record
  it as a **new** key version. **Never re-sign historical events**: old entries
  stay signed by the old key, whose public half remains published, or every
  prior case becomes unverifiable. The report cites the key id per event.
- **`SUPABASE_SERVICE_ROLE_KEY`** — rotate in the Supabase dashboard; it is
  server-side only and appears in no client bundle.

## Incident: suspected cross-tenant leak

1. Confirm with a direct query bypassing the application layer.
2. If RLS is the failing layer, revoke the application role's table grants
   immediately — availability loss is preferable to continued disclosure.
3. Every case read is an evidence event: query `evidence_events` for `action`
   in (`ARTIFACT_DOWNLOADED`, `CASE_VIEWED`) to scope exactly what was accessed.


## Database roles

Three roles. Confusing them disables tenancy silently.

| Connection | Setting | Role | RLS |
|---|---|---|---|
| migrations, bootstrap | `DATABASE_URL` | owner (`headwaters` local, `postgres` on Supabase) | bypassed |
| worker | `DATABASE_URL` | same owner | bypassed — **intentional**, a worker spans every org |
| API request path | `DATABASE_URL_APP` | `headwaters_app` | **enforced** |

### What actually bypasses RLS

Measured, not assumed (`tests/test_db_guards.py::test_force_rls_binds_a_plain_owner_but_not_a_superuser`):

| Role | `FORCE` | Result |
|---|---|---|
| plain table owner | on | policy applies — **FORCE does bind an owner** |
| plain table owner | off | sees everything |
| **SUPERUSER** | on | sees everything |
| role with **BYPASSRLS** | on | sees everything |

So ownership is *not* the hazard — `FORCE ROW LEVEL SECURITY` handles that. The
hazard is **SUPERUSER** or **BYPASSRLS**, which defeat RLS unconditionally. On
Supabase, `postgres` is a superuser: connecting the request path as `postgres`
disables every policy in this system.

### Enforcement

You cannot get this wrong quietly. The API calls
`assert_rls_enforced(get_app_engine())` during startup and **refuses to serve**:

```
UnsafeConnectionError: The request-path database connection authenticates as
'headwaters', which bypasses row-level security (superuser=True, bypassrls=True).
Every tenancy policy would silently stop applying. Point DATABASE_URL_APP at an
unprivileged role such as 'headwaters_app'.
```

Backed by three further layers: `tenant_scope()` raises if handed a system
session; a test forbids routers from importing the privileged session factory;
and `/readyz` reports both connections, so a service that cannot serve an
authenticated read never looks healthy.

### First deploy

The migration creates `headwaters_app` as `NOLOGIN` — a credential must never
live in a migration file. `python -m app.db.bootstrap` grants it a login using
`APP_DB_PASSWORD` and re-applies its grants. It runs after `alembic upgrade
head` and before the server starts, and is idempotent, so it is safe on every
deploy. It re-grants table privileges and then re-revokes `UPDATE`/`DELETE` on
`evidence_events`; **that order is load-bearing** and a test asserts it.

## Queue operations

```sql
-- what is the queue doing
SELECT state, kind, count(*) FROM jobs GROUP BY 1,2 ORDER BY 1,2;

-- jobs that gave up (exhausted retries, or no handler)
SELECT kind, attempts, last_error, created_at FROM jobs
 WHERE state='dead' ORDER BY created_at DESC LIMIT 20;

-- leases held by a worker that is no longer running
SELECT id, kind, locked_by, locked_at FROM jobs
 WHERE state='running' AND locked_at < now() - interval '15 minutes';
```

The worker reclaims stale leases itself every 60 seconds; the query above only
matters if you suspect the sweep is not running. A rising `queued` count is the
earliest signal that Band B enrichment is falling behind.

## Migrations

```bash
make migration m="describe the change"   # autogenerate, then READ THE DIFF
make migrate                             # apply
make drift                               # fail if models and migrations diverged
make migrate-down                        # roll back one
```

Never trust an autogenerated diff on an index or a constraint. `make drift` is
part of the definition of done for any schema change.
