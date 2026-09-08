import type { CaseTimeline } from "@/lib/api";

/**
 * Investigation timeline.
 *
 * Two kinds of entry with very different epistemic status, kept visually
 * distinct: what the *sender* claimed happened, and what this system actually
 * recorded. Presenting them in one undifferentiated list would give the
 * attacker's own timestamps the same standing as our evidence.
 */

const TONE: Record<string, { colour: string; label: string }> = {
  asserted: { colour: "var(--color-critical)", label: "sender-asserted" },
  observed: { colour: "var(--color-trust)", label: "observed" },
  analysis: { colour: "var(--color-accent)", label: "recorded" },
};

export function Timeline({ timeline }: { timeline: CaseTimeline }) {
  return (
    <div className="flex flex-col gap-3 p-4">
      <ol className="flex list-none flex-col">
        {timeline.entries.map((e, i) => {
          const tone = TONE[e.kind] ?? TONE.analysis;
          return (
            <li key={i} className="grid grid-cols-[130px_16px_minmax(0,1fr)] gap-3">
              <span className="pt-0.5 text-right font-mono text-[10px] tabular-nums opacity-55">
                {e.at.replace("T", " ").slice(0, 19)}
              </span>
              <span className="relative flex justify-center">
                <span
                  className="absolute top-2 h-full w-px"
                  style={{ background: "var(--color-line)" }}
                />
                <span
                  className="relative z-10 mt-1.5 h-2 w-2 rounded-full"
                  style={{ background: tone.colour }}
                />
              </span>
              <span className="flex min-w-0 flex-col pb-4">
                <span className="text-sm font-semibold">{e.title}</span>
                <span className="font-mono text-[10px] opacity-55">
                  {e.detail}
                  <span className="ml-2 uppercase" style={{ color: tone.colour }}>
                    {tone.label}
                  </span>
                </span>
              </span>
            </li>
          );
        })}
      </ol>

      <dl className="flex flex-col gap-1 border-t border-[var(--color-line)] pt-3 text-xs opacity-70">
        {Object.entries(timeline.legend).map(([k, v]) => (
          <div key={k} className="flex gap-2">
            <dt
              className="w-20 shrink-0 font-mono text-[10px] uppercase"
              style={{ color: TONE[k]?.colour }}
            >
              {k}
            </dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
