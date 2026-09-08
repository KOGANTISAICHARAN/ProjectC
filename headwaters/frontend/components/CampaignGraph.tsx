import type { CaseGraph } from "@/lib/api";

/**
 * Attack correlation graph.
 *
 * Rendered as deterministic SVG rather than with Cytoscape or React Flow. The
 * payload is emitted in Cytoscape's element shape, so swapping in that library
 * is a renderer change with no API change — but at this size a force layout adds
 * a client-side dependency, a loading state and non-reproducible positions for
 * no gain. A layout that places the same graph identically every time is worth
 * more in a forensic tool than one that animates.
 *
 * Hub indicators (free-mail domains, hyperscaler ASNs, link shorteners) are
 * shown greyed and unlinked: they connect everything to everything, and counting
 * them as evidence collapses the graph into a hairball.
 */

const W = 760;
const H = 420;
const CX = W / 2;
const CY = H / 2;

const KIND_COLOUR: Record<string, string> = {
  case: "var(--color-critical)",
  campaign: "var(--color-accent)",
  ip: "var(--color-trust)",
  domain: "var(--color-warn)",
  url: "var(--color-warn)",
  email: "var(--color-muted, #5d6e68)",
  file_hash: "var(--color-trust)",
  message_id: "var(--color-muted, #5d6e68)",
};

export function CampaignGraph({ graph }: { graph: CaseGraph }) {
  const nodes = graph.elements.nodes;
  const edges = graph.elements.edges;

  // Deterministic layout: root at centre, campaign above it, other cases on an
  // inner ring, indicators on an outer ring. Same input always draws the same
  // picture, which matters when a screenshot ends up in a report.
  const root = nodes.find((n) => n.data.root);
  const campaign = nodes.find((n) => n.data.kind === "campaign");
  const cases = nodes.filter((n) => n.data.kind === "case" && !n.data.root);
  const indicators = nodes.filter(
    (n) => n.data.kind !== "case" && n.data.kind !== "campaign",
  );

  const pos = new Map<string, [number, number]>();
  if (root) pos.set(root.data.id, [CX, CY]);
  if (campaign) pos.set(campaign.data.id, [CX, 52]);

  cases.forEach((n, i) => {
    const a = (Math.PI * 2 * i) / Math.max(1, cases.length) - Math.PI / 2;
    pos.set(n.data.id, [CX + Math.cos(a) * 118, CY + Math.sin(a) * 88]);
  });
  indicators.forEach((n, i) => {
    const a = (Math.PI * 2 * i) / Math.max(1, indicators.length) - Math.PI / 2;
    pos.set(n.data.id, [CX + Math.cos(a) * 300, CY + Math.sin(a) * 168]);
  });

  return (
    <div className="flex flex-col gap-3 p-4">
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full min-w-[560px]"
          role="img"
          aria-label="Indicators and cases connected to this case"
        >
          <rect width={W} height={H} fill="var(--color-surface)" />

          {edges.map((e, i) => {
            const a = pos.get(e.data.source);
            const b = pos.get(e.data.target);
            if (!a || !b) return null;
            const target = nodes.find((n) => n.data.id === e.data.target);
            const hub = target?.data.hub === true;
            return (
              <line
                key={i} x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]}
                stroke={
                  e.data.type === "member_of"
                    ? "var(--color-accent)"
                    : "var(--color-line)"
                }
                strokeWidth={e.data.type === "member_of" ? 2 : 1}
                strokeDasharray={hub ? "3 3" : undefined}
                opacity={hub ? 0.3 : 0.8}
              />
            );
          })}

          {nodes.map((n) => {
            const p = pos.get(n.data.id);
            if (!p) return null;
            const isCase = n.data.kind === "case";
            const isCampaign = n.data.kind === "campaign";
            const hub = n.data.hub === true;
            const r = n.data.root ? 13 : isCase || isCampaign ? 9 : 5;
            return (
              <g key={n.data.id} opacity={hub ? 0.4 : 1}>
                <circle
                  cx={p[0]} cy={p[1]} r={r}
                  fill={hub ? "var(--color-line)" : (KIND_COLOUR[n.data.kind] ?? "var(--color-line)")}
                  stroke={n.data.root ? "var(--color-ink)" : "none"}
                  strokeWidth={2}
                />
                {(isCase || isCampaign) && (
                  <text
                    x={p[0]} y={p[1] + r + 12} textAnchor="middle"
                    className="font-mono" fontSize={10} fill="var(--color-ink)"
                  >
                    {n.data.label}
                    {n.data.score !== undefined && n.data.score !== null
                      ? ` (${n.data.score})`
                      : ""}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] opacity-65">
        {Object.entries(KIND_COLOUR).map(([kind, colour]) => (
          <span key={kind} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2 w-2 rounded-full"
              style={{ background: colour }}
            />
            {kind.replace(/_/g, " ")}
          </span>
        ))}
        <span className="flex items-center gap-1.5 opacity-60">
          <span className="inline-block h-2 w-2 rounded-full bg-[var(--color-line)]" />
          hub (suppressed)
        </span>
      </div>

      <p className="max-w-prose text-xs opacity-70">{graph.note}</p>
    </div>
  );
}
