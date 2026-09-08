import type { Hop, Origin } from "@/lib/api";

/**
 * Infrastructure hop view.
 *
 * Deliberately NOT captioned as a route. The Received chain records a sequence
 * of hosts that handled the message; the packets took an entirely different
 * path, and drawing an arc between countries would assert something the evidence
 * does not support. See docs/CLAIM_CONTRACT.md.
 *
 * The world outline is a coarse equirectangular sketch drawn inline: it exists
 * to give country markers somewhere to sit, and shipping a TopoJSON file plus a
 * mapping library for that would be a lot of weight for a decoration. When no
 * geolocation dataset is installed, the map is replaced by an honest empty state
 * rather than by invented pins.
 */

// Approximate centroids, equirectangular. Enough to place a marker in the right
// part of the world; deliberately not precise, because the underlying data is
// country-granular and pretending otherwise would misrepresent it.
const CENTROIDS: Record<string, [number, number]> = {
  US: [-98, 39], CA: [-106, 56], BR: [-51, -14], GB: [-3, 54], IE: [-8, 53],
  FR: [2, 46], DE: [10, 51], NL: [5, 52], ES: [-3, 40], IT: [12, 42],
  SE: [18, 60], PL: [19, 52], RU: [90, 61], TR: [35, 39], AE: [54, 24],
  IN: [79, 22], CN: [104, 35], JP: [138, 36], KR: [128, 36], SG: [104, 1],
  HK: [114, 22], AU: [133, -25], NZ: [174, -41], ZA: [24, -29], NG: [8, 9],
  EG: [30, 26], KE: [38, 0], ID: [113, -1], MY: [102, 4], VN: [108, 14],
  TH: [101, 15], PH: [122, 12], UA: [32, 49], RO: [25, 46], CH: [8, 47],
};

const W = 720;
const H = 360;

const project = ([lon, lat]: [number, number]): [number, number] => [
  ((lon + 180) / 360) * W,
  ((90 - lat) / 180) * H,
];

export function HopMap({ hops, origin }: { hops: Hop[]; origin: Origin | null }) {
  const located = hops
    .filter((h) => h.country && CENTROIDS[h.country])
    .map((h) => ({ hop: h, point: project(CENTROIDS[h.country as string]) }));

  const boundary = origin?.boundary_hop_seq ?? null;

  if (located.length === 0) {
    return (
      <div className="flex flex-col gap-3 p-4">
        <p className="font-mono text-[11px] uppercase tracking-[0.14em] opacity-55">
          no geographic data
        </p>
        <p className="max-w-prose text-sm opacity-80">
          None of the observed hops resolved to a country. No geolocation dataset is
          installed, and the addresses in this message fall in reserved documentation
          ranges. <b>No location is claimed.</b>
        </p>
        <p className="max-w-prose text-xs opacity-60">
          Install <code>GeoLite2-Country.mmdb</code> and <code>GeoLite2-ASN.mmdb</code>{" "}
          into <code>backend/assets/</code> to enable country-level attribution. Even
          then this view shows the networks that <i>handled</i> the message — never a
          person&rsquo;s location, and never a travel route.
        </p>
        <HopLadder hops={hops} boundary={boundary} />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3 p-4">
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full min-w-[520px]"
          role="img"
          aria-label="Countries of the networks that handled this message"
        >
          <rect width={W} height={H} fill="var(--color-surface)" />
          {[...Array(7)].map((_, i) => (
            <line
              key={`h${i}`} x1={0} x2={W} y1={(H / 6) * i} y2={(H / 6) * i}
              stroke="var(--color-line)" strokeWidth={0.5} opacity={0.5}
            />
          ))}
          {[...Array(13)].map((_, i) => (
            <line
              key={`v${i}`} x1={(W / 12) * i} x2={(W / 12) * i} y1={0} y2={H}
              stroke="var(--color-line)" strokeWidth={0.5} opacity={0.5}
            />
          ))}

          {located.map(({ hop, point }) => {
            const isFeos = hop.observed_ip === origin?.feos_ip;
            const vouched = boundary !== null && hop.seq <= boundary;
            const colour = isFeos
              ? "var(--color-critical)"
              : vouched
                ? "var(--color-trust)"
                : "var(--color-warn)";
            return (
              <g key={hop.seq}>
                {/* Country-granular data gets a radius, not a pin: a sharp point
                    would imply a precision the dataset does not have. */}
                <circle cx={point[0]} cy={point[1]} r={18} fill={colour} opacity={0.15} />
                <circle cx={point[0]} cy={point[1]} r={isFeos ? 7 : 4.5} fill={colour} />
                <text
                  x={point[0]} y={point[1] - 22} textAnchor="middle"
                  className="font-mono" fontSize={11} fill="var(--color-ink)"
                >
                  {hop.country}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="max-w-prose border-l-2 border-[var(--color-warn)] bg-[var(--color-warn)]/10 px-3 py-2 text-xs">
        <b>Infrastructure observed in transit. Not the operator&rsquo;s location.</b> These
        are the countries in which the handling networks are registered, at country
        granularity. Messages do not travel between these points — the packets took an
        unrelated path.
      </p>

      <HopLadder hops={hops} boundary={boundary} />
    </div>
  );
}

function HopLadder({ hops, boundary }: { hops: Hop[]; boundary: number | null }) {
  return (
    <ol className="flex list-none flex-col gap-1 font-mono text-[11px]">
      {hops.map((h) => {
        const vouched = boundary !== null && h.seq <= boundary;
        return (
          <li key={h.seq} className="flex flex-wrap items-baseline gap-x-2">
            <span className="opacity-40">{String(h.seq).padStart(2, "0")}</span>
            <span className="font-semibold">{h.observed_ip ?? "—"}</span>
            {h.asn_org && <span className="opacity-70">{h.asn_org}</span>}
            {h.asn ? <span className="opacity-50">AS{h.asn}</span> : null}
            {h.country && <span className="opacity-70">{h.country}</span>}
            <span
              className="border px-1 text-[9px] uppercase"
              style={{
                color: vouched ? "var(--color-trust)" : "var(--color-critical)",
                borderColor: vouched ? "var(--color-trust)" : "var(--color-critical)",
              }}
            >
              {h.trust_state}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
