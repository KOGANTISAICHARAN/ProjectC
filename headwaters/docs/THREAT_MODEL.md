# Threat model

The input to this system is a live attack, hand-crafted to defeat automated
processing, which has already succeeded against somebody's mail filter. Standard
"validate user input" hygiene is not sufficient.

| Threat | Control | Phase |
|---|---|---|
| Oversized upload exhausting memory | 25 MiB cap enforced before the body is buffered; streamed to object storage, never held whole | 1 |
| Malformed MIME hanging or crashing the parser | Parse in a **subprocess** with `RLIMIT_AS`, `RLIMIT_CPU` and a wall-clock timeout. A killed subprocess is a failed case; a hung API is an outage | 3 |
| Decompression bomb | **Archives are never auto-extracted.** Hash and record metadata only. If extraction is ever added: cap decompressed bytes, nesting depth 2, entry count, abort above 100:1 ratio | 3 |
| Malicious attachment execution | Never executed, never opened, never written with its original extension. Stored as an opaque blob named by SHA-256, always `application/octet-stream` + `Content-Disposition: attachment` | 3 |
| Stored XSS via email HTML | Plain text by default. "Render HTML" is an explicit action that loads sanitised content into a fully sandboxed `<iframe sandbox>` (no `allow-scripts`, no `allow-same-origin`) from a separate origin. `dangerouslySetInnerHTML` is never used | 3, 9 |
| SSRF via extracted URLs | **Never fetched by default.** If redirect resolution is enabled: resolve DNS first, reject `169.254/16`, `127/8`, `10/8`, `172.16/12`, `192.168/16`, `::1`, `fc00::/7`; disable automatic redirects and re-validate **every hop**; cap size and time; egress-restricted worker | 6 |
| ReDoS in IOC/lookalike patterns | Patterns audited for catastrophic backtracking; per-pattern input length caps | 3, 4 |
| Prompt injection against the AI layer | Delimited untrusted body, data-not-instructions framing, strict output schema, verbatim-quote validation, fact stripping. A detected attempt becomes a scored **finding** | 7 |
| Log injection | Client-supplied `X-Request-ID` is UUID-validated, never reflected verbatim | 0 ✅ |
| Header injection on echo | CR/LF stripped from anything written into a header or report | 3 |
| XXE / billion laughs | `defusedxml` from the first line of XML parsing | — |
| Cross-tenant data access | `org_id` filter in the application **and** Postgres RLS with `FORCE`. Two independent layers, because failure here leaks private correspondence | 1 ✅ |
| Request path connected with a privileged role, silently disabling every RLS policy | Separate `DATABASE_URL_APP`; `assert_rls_enforced()` **refuses to start** if that role is SUPERUSER or holds BYPASSRLS; `tenant_scope()` rejects a system session; an AST test forbids routers importing the privileged factory | 1 ✅ |
| Chain of custody rewritten | `UPDATE`/`DELETE` revoked from the app role; re-revoked after every bootstrap, with a test asserting the ordering | 1 ✅ |
| Credential exposure | `OPENAI_API_KEY` and service-role keys are server-side only; `gitleaks` blocks merges; the extension never sends its Google token to our backend | 0 ✅, 10 |
| Wildcard CORS | Explicit allowlist including `chrome-extension://<id>`. A wildcard would let any installed extension call the API with the analyst's token | 0 ✅ |

## Data the system must never store

The user's Google OAuth token; any mailbox content beyond the single message
submitted; passwords; email content, headers or tokens in log lines. Logs carry
identifiers and hashes only.
