"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

const SAMPLES = [
  { key: "bec", label: "CEO impersonation", hint: "every auth check passes" },
  { key: "credential_phish", label: "Credential phishing", hint: "SPF fail, fake helpdesk" },
  { key: "benign", label: "Legitimate newsletter", hint: "false-positive guard" },
  { key: "malformed", label: "Hostile MIME", hint: "must fail safely" },
];

export function Ingest() {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  async function go(request: Promise<Response>, label: string) {
    setBusy(label);
    setError(null);
    try {
      const res = await request;
      const data = await res.json();
      if (!res.ok || !data.case_id) throw new Error(data.error ?? "Analysis failed");
      router.push(`/cases/${data.case_id}`);
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
      setBusy(null);
    }
  }

  function upload(file: File) {
    const body = new FormData();
    body.append("file", file);
    void go(fetch("/api/upload", { method: "POST", body }), file.name);
  }

  function sample(name: string) {
    void go(
      fetch("/api/sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      }),
      name,
    );
  }

  return (
    <section className="flex flex-col gap-4">
      <label
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files?.[0];
          if (file) upload(file);
        }}
        className={`flex cursor-pointer flex-col items-center gap-2 border-2 border-dashed px-6 py-10 text-center transition-colors ${
          dragging ? "border-[var(--color-accent)] bg-[var(--color-accent)]/5" : "border-[var(--color-line)]"
        }`}
      >
        <input
          type="file"
          accept=".eml,message/rfc822,text/plain"
          className="hidden"
          disabled={busy !== null}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); }}
        />
        <span className="text-base font-semibold">
          {busy ? `Analysing ${busy}…` : "Drop a .eml file, or click to choose"}
        </span>
        <span className="text-sm opacity-60">
          Parsed offline. No outbound network call is made to produce the verdict.
        </span>
      </label>

      <div className="flex flex-col gap-2">
        <p className="font-mono text-[11px] uppercase tracking-[0.14em] opacity-55">
          Or analyse a bundled sample
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          {SAMPLES.map((s) => (
            <button
              key={s.key}
              type="button"
              disabled={busy !== null}
              onClick={() => sample(s.key)}
              className="flex flex-col items-start gap-0.5 border border-[var(--color-line)] bg-[var(--color-surface)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent)] disabled:opacity-50"
            >
              <span className="text-sm font-semibold">{s.label}</span>
              <span className="text-xs opacity-60">{s.hint}</span>
            </button>
          ))}
        </div>
      </div>

      {error && (
        <p className="border-l-2 border-[var(--color-critical)] bg-[var(--color-critical)]/10 px-4 py-2 text-sm">
          {error}
        </p>
      )}
    </section>
  );
}
