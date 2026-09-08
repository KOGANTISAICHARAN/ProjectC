# Test fixtures

`.eml` corpus lands here in **Phase 3** (email processing engine):

| File | Purpose |
|------|---------|
| `bec.eml` | The demo case. SPF/DKIM/DMARC all pass on an attacker-registered lookalike domain; forged Received header; injected `Authentication-Results`. |
| `credential_phish.eml` | Second attack class, proves the engine is not BEC-specific. |
| `benign.eml` | A real marketing newsletter with a divergent `Reply-To` — must score in the benign band. This is the false-positive guard. |
| `malformed.eml` | RFC-hostile MIME: unterminated boundaries, bad encodings, absurd nesting. Must fail safely, never hang. |

Every fixture is synthetic. All IP addresses come from RFC 5737 / RFC 3849
documentation ranges and all domains are reserved test names.
