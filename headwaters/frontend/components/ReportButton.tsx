"use client";

import { useState } from "react";

export function ReportButton({ caseId }: { caseId: string }) {
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<{ id: string; sha256: string; version: number } | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);

  async function generate() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ caseId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "Report generation failed");
      setReport({ id: data.report_id, sha256: data.sha256, version: data.version });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-3 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={generate}
          disabled={busy}
          className="border border-[var(--color-accent)] bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
        >
          {busy ? "Generating…" : "Generate forensic report"}
        </button>
        {report && (
          <a
            href={`/reports/${report.id}`}
            target="_blank"
            rel="noreferrer"
            className="text-sm font-semibold underline"
          >
            Open report v{report.version} →
          </a>
        )}
      </div>

      {report && (
        <p className="font-mono text-[10px] opacity-60">
          report sha256 {report.sha256}
        </p>
      )}
      {error && (
        <p className="border-l-2 border-[var(--color-critical)] bg-[var(--color-critical)]/10 px-3 py-2 text-xs">
          {error}
        </p>
      )}
      <p className="max-w-prose text-xs opacity-65">
        Includes the confidence derivation, the annotated Received chain, the chain of
        custody with its Merkle root and public key, and a pre-filled Section 63
        (Bharatiya Sakshya Adhiniyam 2023) electronic-evidence certificate. Generating
        it is itself recorded as an evidence event.
      </p>
    </div>
  );
}
