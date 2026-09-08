# Headwaters

**Email threat detection and forensic intelligence.** Takes a suspicious email
and produces a defensible case file: a trust-boundary origin trace, a campaign
linkage graph, and a tamper-evident chain of custody.

PS26106 — *AI-Powered Email Threat Detection, GeoLocation and Forensic
Intelligence Platform* · Theme: Blockchain & Cybersecurity.

---

## The design principle

> Deterministic forensics establish fact. The AI layer reads intent only.

SPF, DKIM, DMARC, header analysis, Received-chain reconstruction, IP and ASN
attribution, and every risk-score contribution are computed in code. The LLM is
never permitted to decide an authentication result, an IP origin, a geolocation,
or a verdict — it classifies social-engineering intent and writes the analyst's
explanation, capped at 12 of 100 risk points.

The second principle follows from the first: **the system claims only what the
evidence supports.** It reports *probable originating infrastructure* with
published confidence arithmetic, never "the attacker is located here."
See [`docs/CLAIM_CONTRACT.md`](docs/CLAIM_CONTRACT.md).

---

## Quick start

```bash
make ports       # confirm the host ports are free
make up          # build and start db + api + web
make smoke       # verify api -> db and web -> api
```

| Service   | URL                              |
|-----------|----------------------------------|
| Dashboard | http://127.0.0.1:3100            |
| API       | http://127.0.0.1:8000            |
| API docs  | http://127.0.0.1:8000/docs       |
| Postgres  | not published — use `make psql`  |
| Worker    | no port; `docker compose logs worker` |

**Two doors into the product.** The analyst opens the dashboard: score with its
reasoning, the origin trace, findings, evidence. Everyone else gets one button
in Gmail and one sentence telling them what to do — see
[`extension/README.md`](extension/README.md) for the 30-second install.

Ports are configurable (`WEB_PORT`, `API_PORT`) and bound to loopback only. The
dashboard defaults to **3100, not 3000**: port 3000 is the most contended port on
a developer machine, and on macOS another app holding `[::1]:3000` silently beats
Docker's wildcard bind — the dashboard then serves someone else's application
with no error anywhere. `make ports` detects that before it wastes your evening.

`make help` lists every target.

---

## Layout

```
backend/         FastAPI service + worker (one image, two entrypoints)
frontend/        Next.js 15 analyst dashboard
extension/       Chrome MV3 extension (Phase 10)
infrastructure/  render.yaml, Supabase RLS policies
docs/            architecture, claim contract, runbook
```

The one structural rule: **`services/` never imports FastAPI, and `routers/`
never contains logic.** That boundary is why the forensics engine is unit
testable without HTTP, and why the API and the worker can share it.

### Two database connections

`DATABASE_URL` is privileged — migrations, bootstrap, and the worker, which must
drain every organisation's jobs. `DATABASE_URL_APP` is not: it authenticates as
`headwaters_app`, so row-level security applies to every read and write made on
behalf of a user.

The API **refuses to start** if the request-path role can bypass RLS. That check
is not paranoia — the failure it prevents raises nothing, logs nothing, and its
only symptom is one customer reading another's mail. See
[`docs/RUNBOOK.md`](docs/RUNBOOK.md#database-roles).

---

## Build phases

| Phase | Scope | Status |
|------:|-------|--------|
| 0 | Repository, local stack, health checks | ✅ |
| 1 | Schema, migrations, RLS, `jobs` queue, worker | ✅ |
| 2 | Email processing engine (MIME, URLs, attachments, hostile input) | ✅ |
| 3 | SPF / DKIM / DMARC — reported **and** independently recomputed | ✅ |
| 4 | **Trust-boundary origin reconstruction** | ✅ |
| 5 | Explainable risk fusion, 8 groups + corroboration gate | ✅ |
| 6 | OpenAI extraction + narrative, schema-locked and quote-grounded | ✅ |
| 7 | **Evidence chain** — hash-chained, signed, Merkle root, verify | ✅ |
| 8 | **Email DNA + campaign correlation** | ✅ |
| 9 | Analyst dashboard — 11 panels | ✅ |
| 10 | Chrome extension (MV3) | ✅ |
| 11 | Deployment (Vercel · Render · Supabase · Sentry) | ✅ |
| 12 | CI/CD — 3 GitHub Actions workflows | ✅ |
| 13 | Test corpus and coverage | ✅ |

**Deliberately not built**, and visible as such in the UI rather than hidden:
live threat-intelligence feeds, attachment detonation, object storage,
subprocess parser isolation, and authentication (a development identity stub
that refuses to operate in production stands in). See `docs/RUNBOOK.md`.

## The analyst dashboard

Eleven panels per case: verdict, authentication (with the alignment row that
carries the whole lesson), identity, origin with the trust boundary drawn across
the Received chain, infrastructure hops, score contribution by group, findings
with quoted evidence, campaign linkage with the six DNA loci, correlation graph,
investigation timeline, and the chain of custody with a working **Verify** button.

## Security posture

The input to this system is a live attack that has already defeated somebody's
mail filter. It is treated accordingly — parsing runs in a resource-limited
subprocess, archives are never auto-extracted, attachments are never executed,
email HTML is never rendered into the dashboard DOM, and extracted URLs are
never fetched by default. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Licence

Unpublished coursework/hackathon project. All test fixtures are synthetic and
use IANA-reserved documentation ranges.
