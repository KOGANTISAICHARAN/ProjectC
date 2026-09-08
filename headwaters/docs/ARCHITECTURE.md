# Architecture

## Two bands

**Band A — synchronous, offline-safe, target p95 < 2 s.** Acquire, hash, parse,
header forensics, authentication evaluation as reported, IOC extraction, origin
reconstruction, offline geo/ASN lookup, risk fusion. No outbound network calls.
This band produces a verdict that is complete and defensible on its own.

**Band B — asynchronous, allowed to fail.** DNS, RDAP, threat intelligence, the
OpenAI calls, DNA and campaign linkage. Each result *upgrades* the case and is
streamed to the UI over SSE. A failure marks the group unavailable and lowers
the case's data-completeness figure — it never blocks or invalidates Band A.

Consequence: unplug the network mid-demo and the product still works, degraded
and honest about it. That property is worth more than any single feature.

## Decision log

### Why the data layer is synchronous
The heavy work is CPU-bound (MIME parsing, DKIM verification, fingerprinting),
not I/O concurrency, and FastAPI runs sync endpoints in a threadpool. Async
adds no throughput here, and asyncpg's prepared-statement cache is incompatible
with transaction-mode poolers such as Supabase's Supavisor — a real, hard-to-
diagnose failure. Sync SQLAlchemy + psycopg3 removes that class of bug.

### Why `NullPool` behind a pooler
Supavisor in transaction mode already pools server-side. Layering SQLAlchemy's
pool on top exhausts the upstream limit the moment a second container starts.
`app/db/session.py` detects a pooler host and switches automatically.

### Why the queue is a Postgres table
`SELECT ... FOR UPDATE SKIP LOCKED` is transactional with the case row (a case
and its job are created atomically), needs no broker, survives restarts, and is
correct under concurrent workers. Redis + `arq` is the right upgrade at roughly
20 jobs/second — which means real customers, not a hackathon.

### Why the dashboard proxies the API
`API_BASE_URL` has no `NEXT_PUBLIC_` prefix. Route handlers call FastAPI
server-side so no upstream URL, service key, or OpenAI credential can reach the
client bundle. Only the Supabase anon key — designed for client use and governed
by RLS — is public.

### Why one image runs both API and worker
Two entrypoints over one codebase means `services/` can never drift between the
process that accepts the upload and the process that enriches it.

### Why `services/` may not import FastAPI
The forensics engine is the most valuable and most test-heavy code in the
project. Keeping it free of the web framework means it is unit testable without
HTTP, reusable from the worker and a future CLI, and portable if the transport
ever changes.

### Why there are two database connections

`DATABASE_URL` is privileged (migrations, bootstrap, worker); `DATABASE_URL_APP`
is not (every read and write on behalf of a user). They are separate pools with
separate session factories, and `tenant_scope()` raises if handed a session from
the wrong one.

The asymmetry is deliberate. A worker must drain every organisation's jobs, so
constraining it to one tenant makes it useless. A request must be constrained to
one tenant, or the only boundary left is whether a developer remembered a
`WHERE org_id` clause. Those are opposite requirements and cannot share a
connection.

Making local development use the unprivileged role too means the tenancy path is
exercised on every request during ordinary work, rather than only in the test
suite — which is where this class of bug otherwise hides until production.
