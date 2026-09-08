"use client";

import { useState } from "react";

interface EventRow {
  seq: number;
  ts_utc: string;
  actor: string;
  action: string;
  payload_hash: string;
  prev_hash: string | null;
  entry_hash: string;
  signing_key_id: string | null;
}

interface Link {
  seq: number;
  action: string;
  hash_ok: boolean;
  link_ok: boolean;
  signature_ok: boolean;
  ok: boolean;
  reason: string | null;
}

interface Verification {
  intact: boolean;
  event_count: number;
  merkle_root: string | null;
  signing_key_id: string;
  public_key: string;
  first_broken_seq: number | null;
  summary: string;
  links: Link[];
}

export function EvidenceChain({ caseId, events }: { caseId: string; events: EventRow[] }) {
  const [result, setResult] = useState<Verification | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function call(action: "verify" | "tamper") {
    setBusy(action);
    try {
      const res = await fetch("/api/evidence", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ caseId, action, seq: 2 }),
      });
      const data = await res.json();
      if (action === "tamper") {
        setNote(data.note ?? data.detail ?? "Tampered.");
        setResult(null);
      } else {
        setResult(data as Verification);
        setNote(null);
      }
    } finally {
      setBusy(null);
    }
  }

  const bySeq = new Map(result?.links.map((l) => [l.seq, l]) ?? []);

  return (
    <div className="flex flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--color-line)] px-4 py-3">
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => call("verify")}
          className="border border-[var(--color-accent)] bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
        >
          {busy === "verify" ? "Verifying…" : "Verify integrity"}
        </button>
        <button
          type="button"
          disabled={busy !== null}
          onClick={() => call("tamper")}
          className="border border-[var(--color-critical)] px-3 py-2 text-xs font-semibold disabled:opacity-50"
          style={{ color: "var(--color-critical)" }}
          title="Alters one stored event using the privileged system connection, to demonstrate detection"
        >
          {busy === "tamper" ? "…" : "Tamper with event 2"}
        </button>
        <span className="text-xs opacity-55">
          {events.length} events · hash-chained · Ed25519 signed
        </span>
      </div>

      {note && (
        <p className="border-b border-[var(--color-line)] bg-[var(--color-warn)]/10 px-4 py-3 text-xs">
          {note} <b>Now press Verify integrity.</b>
        </p>
      )}

      {result && (
        <div
          className="border-b border-[var(--color-line)] px-4 py-3"
          style={{
            background: result.intact
              ? "color-mix(in srgb, var(--color-accent) 10%, transparent)"
              : "color-mix(in srgb, var(--color-critical) 12%, transparent)",
          }}
        >
          <p
            className="font-mono text-[11px] uppercase tracking-[0.14em]"
            style={{ color: result.intact ? "var(--color-accent)" : "var(--color-critical)" }}
          >
            {result.intact ? "chain intact" : `chain broken at event ${result.first_broken_seq}`}
          </p>
          <p className="mt-1 max-w-prose text-sm">{result.summary}</p>
          <dl className="mt-2 flex flex-col gap-0.5 font-mono text-[10px] opacity-65">
            <div className="flex gap-2">
              <dt>merkle root</dt>
              <dd className="break-all">{result.merkle_root}</dd>
            </div>
            <div className="flex gap-2">
              <dt>signing key</dt>
              <dd>{result.signing_key_id}</dd>
            </div>
          </dl>
        </div>
      )}

      <ol className="flex list-none flex-col font-mono text-[11px]">
        {events.map((e) => {
          const link = bySeq.get(e.seq);
          const failed = link && !link.ok;
          return (
            <li
              key={e.seq}
              className="grid grid-cols-[24px_minmax(0,1fr)_auto] items-center gap-3 border-b border-[var(--color-line)]/40 px-4 py-2 last:border-b-0"
              style={{
                background: failed
                  ? "color-mix(in srgb, var(--color-critical) 12%, transparent)"
                  : undefined,
              }}
            >
              <span className="opacity-40">{e.seq}</span>
              <span className="min-w-0 truncate">
                <b>{e.action}</b>
                <span className="opacity-55"> · {e.actor}</span>
                <span className="opacity-40"> · {e.entry_hash.slice(0, 16)}…</span>
              </span>
              <span className="shrink-0">
                {link ? (
                  <span
                    className="border px-1.5 py-0.5 text-[9px] uppercase tracking-[0.08em]"
                    style={{
                      color: link.ok ? "var(--color-accent)" : "var(--color-critical)",
                      borderColor: link.ok ? "var(--color-accent)" : "var(--color-critical)",
                    }}
                  >
                    {link.ok ? "pass" : "fail"}
                  </span>
                ) : (
                  <span className="opacity-30">—</span>
                )}
              </span>
            </li>
          );
        })}
      </ol>

      {result && !result.intact && (
        <p className="border-t border-[var(--color-line)] px-4 py-3 text-xs opacity-70">
          The application role could not have made this change: <code>UPDATE</code> and{" "}
          <code>DELETE</code> on the custody log are revoked from it. The tamper button
          uses the privileged system connection specifically to prove the detection works.
        </p>
      )}
    </div>
  );
}
