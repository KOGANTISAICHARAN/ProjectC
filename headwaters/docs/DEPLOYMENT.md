# Deployment

| Component | Where | Why |
|---|---|---|
| Dashboard | **Vercel** | First-party Next.js host; streaming and route handlers work with no adapter |
| API + worker | **Render** (Docker) | One image, two start commands; background workers are a first-class service type |
| Postgres, Auth, Storage | **Supabase** | Collapses three integrations into one account |
| Errors | **Sentry** | Free tier, twenty minutes to wire, pays for itself immediately |

Everything also runs locally with `make up`. Keep that working: it is the
fallback when a deploy or the venue's network fails.

---

## 1 · Database (Supabase)

Create a project, then from the SQL editor or `psql`:

```sql
-- Applied by `alembic upgrade head`; this only grants the login credential the
-- migration deliberately does not contain.
ALTER ROLE headwaters_app LOGIN PASSWORD '<from your secret store>';
```

Two connection strings, and **the distinction is a security control**:

```
DATABASE_URL      postgresql+psycopg://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres
DATABASE_URL_APP  postgresql+psycopg://headwaters_app:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres
```

Use the **Supavisor transaction pooler on port 6543**, not 5432. The application
detects a pooler host and switches to `NullPool`; layering SQLAlchemy's own pool
on top of a server-side pool exhausts the upstream limit as soon as a second
container starts.

> **The one mistake that silently disables tenancy.** `postgres` is a superuser
> on Supabase, and a superuser bypasses row-level security unconditionally —
> `FORCE ROW LEVEL SECURITY` binds a plain table owner but cannot bind a
> superuser. If `DATABASE_URL_APP` points at `postgres`, every policy stops
> applying and the only boundary left is whether a developer remembered a
> `WHERE org_id`. The API calls `assert_rls_enforced()` at startup and **refuses
> to serve** in that case; see `docs/RUNBOOK.md` § Database roles.

## 2 · Backend (Render)

```bash
# Generate the evidence signing key ONCE and store it as a secret.
python -c "import base64;from cryptography.hazmat.primitives.asymmetric.ed25519 \
import Ed25519PrivateKey as K;from cryptography.hazmat.primitives.serialization \
import Encoding,PrivateFormat,NoEncryption;\
print(base64.b64encode(K.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode())"
```

Render → New → Blueprint → select this repository. It reads
`infrastructure/render.yaml` and provisions the web service and the worker. Fill
every variable marked `sync: false`.

**Never rotate `EVIDENCE_SIGNING_KEY` by re-signing history.** Old events stay
signed by the old key, whose public half remains published in reports — otherwise
every prior case becomes unverifiable, which is indistinguishable from tampering.

## 3 · Frontend (Vercel)

Import the repository, set the root directory to `frontend/`, and configure:

```
API_BASE_URL                 https://<render-service>.onrender.com   # NO NEXT_PUBLIC_ prefix
NEXT_PUBLIC_SUPABASE_URL     https://<ref>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY  <anon key>
```

The missing prefix is deliberate: the browser never talks to FastAPI directly,
so no upstream URL or credential can reach the client bundle. Only the anon key —
designed for client use and governed by RLS — is public.

Then set `ALLOWED_ORIGINS` on Render to the Vercel URL **plus** the extension
origin:

```
ALLOWED_ORIGINS=https://<app>.vercel.app,chrome-extension://<extension-id>
```

Never a wildcard: any extension installed in the analyst's browser could
otherwise call the API with their token.

## 4 · Optional datasets

Drop `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` into `backend/assets/` to
enable country-level network attribution. Without them the platform falls back to
a small bundled table and **labels every value with its source**, so a reader can
always tell a geolocation lookup from a fallback. It never invents a country.

## 5 · Verify the deploy

```bash
curl -fsS https://<api>/healthz      # process alive
curl -fsS https://<api>/readyz       # {"database": true, "database_app": true}
```

`/readyz` reports **both** connections. A service that cannot serve an
authenticated read must never look healthy.

## Cost

| | Hackathon | Small production (100 analysts, ~5k emails/month) |
|---|---:|---:|
| Vercel | $0 | $20 |
| Render web | $7 | $50 |
| Render worker | $0 (folded in) | $25 |
| Supabase | $0 | $25 |
| OpenAI | ~$3 | ~$13 |
| Sentry | $0 | $26 |
| **Total** | **~$10/mo** | **~$160/mo** |

The LLM is not the dominant line, because of two architectural choices: the small
model runs on the call that always fires, and the narrative call is gated on the
deterministic score. Most reported mail is benign, so that gate removes roughly
three quarters of narrative spend with no reader affected.
