import Link from "next/link";
import { Ingest } from "@/components/Ingest";
import { getApiHealth, listCases } from "@/lib/api";

export const dynamic = "force-dynamic";

const BAND_COLOR: Record<string, string> = {
  benign: "var(--color-accent)",
  suspicious: "var(--color-warn)",
  likely_malicious: "var(--color-warn)",
  high: "var(--color-critical)",
  critical: "var(--color-critical)",
};

export default async function Home() {
  const [health, cases] = await Promise.all([getApiHealth(), listCases()]);

  return (
    <main className="mx-auto flex max-w-4xl flex-col gap-10 px-6 py-14">
      <header className="flex flex-col gap-3 border-b-2 border-current pb-6">
        <p className="font-mono text-[11px] uppercase tracking-[0.14em] opacity-55">
          PS26106 · email threat detection &amp; forensic intelligence
        </p>
        <h1 className="text-5xl font-semibold tracking-tight">Headwaters</h1>
        <p className="max-w-prose text-base opacity-80">
          Deterministic forensics establish fact. The AI layer reads intent only.
          The system reports how far upstream the evidence actually reaches — and
          refuses to go further.
        </p>
      </header>

      <Ingest />

      <section className="flex flex-col gap-3">
        <h2 className="font-mono text-[11px] uppercase tracking-[0.14em] opacity-55">
          Cases ({cases.length})
        </h2>
        {cases.length === 0 ? (
          <p className="border border-[var(--color-line)] bg-[var(--color-surface)] px-4 py-6 text-sm opacity-60">
            No cases yet. Analyse a sample above.
          </p>
        ) : (
          <ul className="flex list-none flex-col border border-[var(--color-line)] bg-[var(--color-surface)]">
            {cases.map((c) => (
              <li key={c.id} className="border-b border-[var(--color-line)]/50 last:border-b-0">
                <Link
                  href={`/cases/${c.id}`}
                  className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-4 px-4 py-3 transition-colors hover:bg-[var(--color-accent)]/5"
                >
                  <span
                    className="w-12 text-right font-mono text-lg font-bold tabular-nums"
                    style={{ color: BAND_COLOR[c.band ?? ""] ?? "inherit" }}
                  >
                    {c.score ?? "—"}
                  </span>
                  <span className="flex min-w-0 flex-col">
                    <span className="truncate text-sm font-semibold">
                      {c.subject ?? "(no subject)"}
                    </span>
                    <span className="truncate font-mono text-[11px] opacity-55">
                      {c.case_ref} · {c.from_address ?? "unknown sender"}
                    </span>
                  </span>
                  <span
                    className="shrink-0 border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em]"
                    style={{
                      color: BAND_COLOR[c.band ?? ""] ?? "inherit",
                      borderColor: BAND_COLOR[c.band ?? ""] ?? "currentColor",
                    }}
                  >
                    {(c.classification ?? c.band ?? "").replace(/_/g, " ")}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      <footer className="flex flex-wrap gap-x-6 gap-y-1 border-t border-[var(--color-line)] pt-4 font-mono text-[11px] opacity-50">
        <span>api {health.reachable ? "reachable" : "unreachable"}</span>
        <span>db {health.database ? "ready" : "unready"}</span>
        <span>rls path {health.databaseApp ? "ready" : "unready"}</span>
        <span>{health.environment ?? "—"}</span>
      </footer>
    </main>
  );
}
