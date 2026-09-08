# Infrastructure

| File | Purpose | Phase |
|---|---|---|
| `render.yaml` | Render Blueprint: web service, background worker, environment group | 11 |
| `supabase/policies.sql` | Row-level security policies, reviewed like application code | 2 |
| `scripts/` | `seed_corpus.py`, `warm_cache.py`, `rotate_keys.sh` | 6, 8 |

Deployment targets are fixed by the approved architecture: **Vercel** (frontend),
**Render** (API + worker, Docker), **Supabase** (Postgres + Auth + Storage),
**Sentry** (errors). Rationale and rejected alternatives are in the production
plan; this directory holds only the executable form.
