import type { Hop, Origin } from "@/lib/api";

/**
 * The signature visual: the Received chain with the trust boundary drawn across
 * it. Everything above the line is testimony from infrastructure we recognise;
 * everything below it was written by the sender.
 */
export function ReceivedChain({ hops, origin }: { hops: Hop[]; origin: Origin | null }) {
  const boundary = origin?.boundary_hop_seq ?? null;

  return (
    <ol className="flex list-none flex-col border border-[var(--color-line)] bg-[var(--color-surface)] font-mono text-xs">
      {hops.map((hop) => {
        const vouched = boundary !== null && hop.seq < boundary;
        const isBoundary = boundary !== null && hop.seq === boundary;
        const forged = hop.trust_state === "forged" || hop.anomalies.length > 0;
        const isFeos = origin?.feos_ip !== null && hop.observed_ip === origin?.feos_ip;

        return (
          <li key={hop.seq} className="contents">
            {isBoundary && hop.seq === boundary && null}
            <div
              className={`grid grid-cols-[28px_minmax(0,1fr)_auto] items-center gap-3 border-b border-[var(--color-line)]/50 px-4 py-2.5 ${
                vouched || isBoundary
                  ? "bg-[var(--color-trust)]/10"
                  : forged
                    ? "bg-[var(--color-critical)]/10"
                    : ""
              } ${isFeos ? "shadow-[inset_3px_0_0_var(--color-critical)]" : ""}`}
            >
              <span className="opacity-40">{String(hop.seq).padStart(2, "0")}</span>
              <span className="min-w-0 overflow-x-auto whitespace-nowrap">
                {hop.observed_ip ? (
                  <span className="font-semibold">{hop.observed_ip}</span>
                ) : (
                  <span className="opacity-40">no peer address recorded</span>
                )}
                <span className="opacity-60"> → {hop.by_host ?? "unknown"}</span>
                {hop.hop_ts_utc && (
                  <span className="opacity-40">
                    {"  "}
                    {new Date(hop.hop_ts_utc).toISOString().slice(11, 19)}
                  </span>
                )}
              </span>
              <span className="flex shrink-0 gap-1.5">
                {isFeos && <Chip tone="critical">FEOS</Chip>}
                {forged && <Chip tone="critical">forged</Chip>}
                <Chip tone={vouched || isBoundary ? "trust" : "muted"}>
                  {hop.trust_state}
                </Chip>
              </span>
            </div>
            {isBoundary && (
              <div className="bg-[var(--color-ink)] px-4 py-1.5 text-center font-mono text-[10px] uppercase tracking-[0.16em] text-[var(--color-paper)] dark:bg-[var(--color-accent)] dark:text-[#08110e]">
                ↑ vouched-for testimony · trust boundary · sender-asserted ↓
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function Chip({ children, tone }: { children: React.ReactNode; tone: "critical" | "trust" | "muted" }) {
  const color =
    tone === "critical"
      ? "var(--color-critical)"
      : tone === "trust"
        ? "var(--color-trust)"
        : "currentColor";
  return (
    <span
      className="border px-1.5 py-0.5 text-[9px] uppercase tracking-[0.08em]"
      style={{ color, borderColor: color, opacity: tone === "muted" ? 0.5 : 1 }}
    >
      {children}
    </span>
  );
}
