import Link from "next/link";
import type { Campaign } from "@/lib/api";

const LOCUS_NAME: Record<string, string> = {
  i: "infrastructure",
  d: "identity",
  n: "naming",
  m: "tooling",
  c: "content",
  p: "payload",
};
const ORDER = ["i", "d", "n", "m", "c", "p"];

/**
 * Campaign linkage.
 *
 * The barcode makes the point without anyone reading a number: six bands, one
 * per locus, and related messages visibly share the tooling band while the
 * identity band is completely different.
 */
export function CampaignPanel({
  campaign,
  currentCaseId,
}: {
  campaign: Campaign;
  currentCaseId: string;
}) {
  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <span className="font-mono text-lg font-bold">{campaign.name}</span>
        <span className="text-sm opacity-70">
          {campaign.member_count} cases · highest score {campaign.max_score}
        </span>
      </div>
      <p className="max-w-prose text-sm opacity-80">
        Linked by <b>{campaign.summary}</b>
      </p>

      <div className="flex flex-col gap-2">
        {campaign.members.map((m) => {
          const isCurrent = m.case_id === currentCaseId;
          return (
            <div
              key={m.case_id}
              className="grid gap-2 border border-[var(--color-line)] px-3 py-2.5 sm:grid-cols-[150px_minmax(0,1fr)] sm:items-center"
              style={{
                background: isCurrent
                  ? "color-mix(in srgb, var(--color-accent) 8%, transparent)"
                  : undefined,
              }}
            >
              <div className="flex flex-col">
                <Link
                  href={`/cases/${m.case_id}`}
                  className="font-mono text-xs font-semibold hover:underline"
                >
                  {m.case_ref}
                  {isCurrent && <span className="opacity-55"> (this case)</span>}
                </Link>
                <span className="font-mono text-[10px] opacity-55">
                  score {m.score} · DNA {m.dna_score.toFixed(3)}
                </span>
              </div>

              <div className="flex flex-wrap gap-3">
                {ORDER.map((k) => {
                  const v = m.locus_breakdown[k] ?? 0;
                  return (
                    <div key={k} className="flex flex-col gap-0.5" title={LOCUS_NAME[k]}>
                      <div
                        className="h-6 w-9 border"
                        style={{
                          borderColor:
                            v >= 0.6 ? "var(--color-accent)" : "var(--color-line)",
                          background:
                            v >= 0.6
                              ? "var(--color-accent)"
                              : v > 0
                                ? "color-mix(in srgb, var(--color-accent) 25%, transparent)"
                                : "transparent",
                        }}
                      />
                      <span className="text-center font-mono text-[9px] uppercase opacity-60">
                        {k}
                      </span>
                      <span className="text-center font-mono text-[9px] tabular-nums opacity-45">
                        {v.toFixed(2)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      <p className="max-w-prose border-l-2 border-[var(--color-warn)] bg-[var(--color-warn)]/10 px-3 py-2 text-xs">
        <b>{campaign.caveat}</b>
      </p>

      <p className="max-w-prose text-xs opacity-65">
        The <b>tooling</b> band (m) is identical across these cases while the{" "}
        <b>identity</b> band (d) is zero — the domains, addresses and IP ranges were
        rotated between waves, but the sending software was not. Matching on the
        toolchain is what survives that rotation.
      </p>
    </div>
  );
}
