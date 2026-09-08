import Link from "next/link";
import { notFound } from "next/navigation";
import { ReceivedChain } from "@/components/ReceivedChain";
import { EvidenceChain } from "@/components/EvidenceChain";
import { CampaignGraph } from "@/components/CampaignGraph";
import { CampaignPanel } from "@/components/CampaignPanel";
import { HopMap } from "@/components/HopMap";
import { Timeline } from "@/components/Timeline";
import { ReportButton } from "@/components/ReportButton";
import { getCampaign, getCase, getEvidence, getGraph, getTimeline } from "@/lib/api";

export const dynamic = "force-dynamic";

const BAND_COLOR: Record<string, string> = {
  benign: "var(--color-accent)",
  suspicious: "var(--color-warn)",
  likely_malicious: "var(--color-warn)",
  high: "var(--color-critical)",
  critical: "var(--color-critical)",
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default async function CasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [c, events, campaign, graph, timeline] = await Promise.all([
    getCase(id),
    getEvidence(id),
    getCampaign(id),
    getGraph(id),
    getTimeline(id),
  ]);
  if (!c) notFound();

  const colour = BAND_COLOR[c.band ?? ""] ?? "inherit";
  const findings = [...c.findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
  );
  const groups = Object.entries(c.group_contributions).sort((a, b) => b[1] - a[1]);

  // The demo's central point, made explicit rather than left for the viewer to
  // infer: authentication can pass completely while the message impersonates
  // someone. Surfaced only when BOTH are true.
  // Only the AS-REPORTED rows count here: Band B adds independently recomputed
  // rows whose `result_reported` is null, and requiring every row to be "pass"
  // silently suppressed this callout the moment re-verification was added.
  const reported = c.auth_results.filter((a) => a.result_reported !== null);
  const authPassed =
    reported.length > 0 && reported.every((a) => a.result_reported === "pass");
  const impersonation =
    c.findings.find((f) => f.rule_id === "IDENT_LOOKALIKE_DOMAIN") ??
    c.findings.find((f) => f.rule_id === "IDENT_PROTECTED_DISPLAY_NAME") ??
    null;
  const maxGroup = Math.max(1, ...groups.map(([, v]) => v));

  return (
    <main className="mx-auto flex max-w-4xl flex-col gap-8 px-6 py-12">
      <Link href="/" className="font-mono text-[11px] uppercase tracking-[0.12em] opacity-55 hover:opacity-100">
        ← all cases
      </Link>

      {/* verdict */}
      <header className="flex flex-col gap-4 border-b-2 border-current pb-6">
        <p className="font-mono text-[11px] uppercase tracking-[0.14em] opacity-55">
          {c.case_ref} · weights {c.weights_version} · completeness {c.data_completeness}/8
        </p>
        <div className="flex flex-wrap items-baseline gap-x-5 gap-y-2">
          <span className="font-mono text-6xl font-bold tabular-nums" style={{ color: colour }}>
            {c.score}
          </span>
          <span className="text-2xl font-semibold uppercase tracking-wide" style={{ color: colour }}>
            {(c.band ?? "").replace(/_/g, " ")}
          </span>
          <span className="border px-2 py-1 font-mono text-[11px] uppercase tracking-[0.08em]"
                style={{ color: colour, borderColor: colour }}>
            {(c.classification ?? "").replace(/_/g, " ")}
          </span>
        </div>
        <p className="text-lg">{c.subject ?? "(no subject)"}</p>
      </header>

      {/* the teaching panel: authentication vs alignment */}
      <Panel title="Authentication">
        {authPassed && impersonation && (
          <div className="border-b border-[var(--color-line)] bg-[var(--color-critical)]/10 px-4 py-3">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em]" style={{ color: "var(--color-critical)" }}>
              every check below passed — and the message is still hostile
            </p>
            <p className="mt-1 max-w-prose text-sm opacity-85">
              Authentication passed <b>for a domain the sender controls</b>. These
              checks ask whether a domain&rsquo;s paperwork matches itself, never
              whether the sender is who they claim to be. {impersonation.title}.
            </p>
          </div>
        )}
        {c.auth_results.length === 0 ? (
          <p className="px-4 py-3 text-sm opacity-60">
            No Authentication-Results from recognised infrastructure. Absence of
            evidence, not evidence of forgery.
          </p>
        ) : (
          <div className="divide-y divide-[var(--color-line)]/50">
            {c.auth_results.map((a, i) => (
              <div key={i} className="grid gap-1 px-4 py-3 sm:grid-cols-[90px_auto_minmax(0,1fr)] sm:items-center sm:gap-4">
                <span className="font-mono text-xs uppercase tracking-[0.1em] opacity-60">
                  {a.mechanism}
                </span>
                <span className="font-mono text-sm font-semibold"
                      style={{ color: a.result_reported === "pass" ? "var(--color-accent)" : "var(--color-critical)" }}>
                  {a.result_reported}
                </span>
                <span className="text-xs opacity-70">
                  {a.aligned === false ? (
                    <b style={{ color: "var(--color-critical)" }}>
                      not aligned to the identity shown to the recipient
                      {a.d_domain ? ` (passed for ${a.d_domain})` : ""}
                    </b>
                  ) : a.aligned === true ? (
                    "aligned to the From domain"
                  ) : (
                    "alignment not determinable"
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* identity */}
      <Panel title="Identity">
        <dl className="divide-y divide-[var(--color-line)]/50 font-mono text-xs">
          <Row label="From" value={c.from_address} />
          <Row label="Reply-To" value={c.reply_to} warn={!!c.reply_to} />
          <Row label="Return-Path" value={c.return_path} />
          <Row label="Message-ID" value={c.message_id} />
        </dl>
      </Panel>

      {/* origin — the differentiator */}
      <Panel title="Origin · trust boundary">
        {c.origin ? (
          <div className="flex flex-col gap-4 p-4">
            <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
              <span className="font-mono text-xl font-bold">
                {c.origin.feos_ip ?? "not determinable"}
              </span>
              <span className="font-mono text-sm opacity-70">
                confidence {c.origin.confidence}%
              </span>
              {!c.origin.geo_available && (
                <span className="border border-current px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.08em] opacity-60">
                  geolocation dataset not installed
                </span>
              )}
            </div>
            <p className="max-w-prose text-sm">
              {c.origin.feos_ip
                ? "This is the furthest back we can honestly trace the email — the address the last mail server we trust actually saw. It is a machine on the internet, not a person's location."
                : "We could not recognise any mail server in this email's delivery trail, so we will not guess where it came from."}
            </p>
            <details className="max-w-prose">
              <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-[0.1em] opacity-50 hover:opacity-80">
                the precise claim
              </summary>
              <p className="mt-1.5 text-xs opacity-70">{c.origin.claim_text}</p>
            </details>

            <details className="text-xs">
              <summary className="cursor-pointer font-mono uppercase tracking-[0.1em] opacity-60">
                how this confidence was computed
              </summary>
              <ul className="mt-2 flex list-none flex-col gap-0.5 font-mono">
                {Object.entries(c.origin.confidence_breakdown).map(([k, v]) => (
                  <li key={k} className="flex justify-between border-b border-[var(--color-line)]/40 py-0.5">
                    <span className="opacity-70">{k.replace(/_/g, " ")}</span>
                    <span className="tabular-nums" style={{ color: v < 0 ? "var(--color-critical)" : "inherit" }}>
                      {v > 0 ? `+${v}` : v}
                    </span>
                  </li>
                ))}
                <li className="flex justify-between py-1 font-bold">
                  <span>clamped to 5–95, never 100</span>
                  <span className="tabular-nums">{c.origin.confidence}</span>
                </li>
              </ul>
            </details>

            <ReceivedChain hops={c.hops} origin={c.origin} />
          </div>
        ) : (
          <p className="px-4 py-3 text-sm opacity-60">No origin assessment.</p>
        )}
      </Panel>

      <Panel title="Infrastructure hops">
        <HopMap hops={c.hops} origin={c.origin} />
      </Panel>

      {/* score breakdown */}
      <Panel title="Score contribution by group">
        <div className="flex flex-col divide-y divide-[var(--color-line)]/50">
          {groups.map(([group, value]) => (
            <div key={group} className="grid grid-cols-[minmax(110px,1fr)_minmax(60px,2fr)_44px] items-center gap-3 px-4 py-2 text-sm">
              <span className="capitalize">{group.replace(/_/g, " ")}</span>
              <span className="h-2 border border-[var(--color-line)] bg-[var(--color-line)]/20">
                <span className="block h-full" style={{ width: `${(value / maxGroup) * 100}%`, background: colour }} />
              </span>
              <span className="text-right font-mono text-xs tabular-nums">{value.toFixed(1)}</span>
            </div>
          ))}
        </div>
      </Panel>

      {/* findings */}
      <Panel title={`Findings (${findings.length})`}>
        <div className="flex flex-col divide-y divide-[var(--color-line)]/50">
          {findings.map((f, i) => (
            <article key={i} className="flex flex-col gap-1.5 px-4 py-3">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em]"
                      style={{
                        color: f.severity === "critical" || f.severity === "high"
                          ? "var(--color-critical)" : "var(--color-warn)",
                        borderColor: f.severity === "critical" || f.severity === "high"
                          ? "var(--color-critical)" : "var(--color-warn)",
                      }}>
                  {f.severity}
                </span>
                <span className="text-sm font-semibold">{f.title}</span>
                <span className="ml-auto font-mono text-[11px] opacity-50">{f.rule_id}</span>
              </div>
              {/* Plain sentence first, technical account behind a toggle. Leading
                  with the technical text means nobody reads it; removing it
                  means the finding cannot be defended under questioning. */}
              {f.plain_summary && (
                <p className="max-w-prose text-sm">{f.plain_summary}</p>
              )}
              {f.detail && (
                <details className="max-w-prose">
                  <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-[0.1em] opacity-50 hover:opacity-80">
                    technical detail
                  </summary>
                  <p className="mt-1.5 text-xs opacity-70">{f.detail}</p>
                </details>
              )}
              {f.evidence_quote && (
                <p className="border-l-2 border-[var(--color-warn)] bg-[var(--color-warn)]/10 px-3 py-1.5 font-mono text-[11px]">
                  “{f.evidence_quote}”
                </p>
              )}
              {f.mitre_technique && (
                <span className="font-mono text-[10px] opacity-50">MITRE {f.mitre_technique}</span>
              )}
            </article>
          ))}
        </div>
      </Panel>

      {campaign && (
        <Panel title="Campaign · Email DNA">
          <CampaignPanel campaign={campaign} currentCaseId={c.id} />
        </Panel>
      )}

      {graph && graph.elements.nodes.length > 1 && (
        <Panel title="Correlation graph">
          <CampaignGraph graph={graph} />
        </Panel>
      )}

      {timeline && timeline.entries.length > 0 && (
        <Panel title="Investigation timeline">
          <Timeline timeline={timeline} />
        </Panel>
      )}

      <Panel title="Evidence · chain of custody">
        <EvidenceChain caseId={c.id} events={events} />
      </Panel>

      <Panel title="Forensic report">
        <ReportButton caseId={c.id} />
      </Panel>

      <p className="max-w-prose border-l-2 border-[var(--color-line)] pl-4 text-xs italic opacity-55">
        Deferred and not represented above: threat-intelligence correlation and
        campaign linkage (both Band B), geolocation, the AI intent layer, and the
        signed evidence chain. Data completeness is reported as {c.data_completeness}/8
        so a partially-evidenced case is never mistaken for a fully-evidenced one.
      </p>
    </main>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border border-[var(--color-line)] bg-[var(--color-surface)]">
      <h2 className="border-b border-[var(--color-line)] bg-black/[0.03] px-4 py-2 font-mono text-[11px] uppercase tracking-[0.14em] opacity-70 dark:bg-white/[0.03]">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Row({ label, value, warn }: { label: string; value: string | null; warn?: boolean }) {
  return (
    <div className="grid grid-cols-[100px_minmax(0,1fr)] gap-3 px-4 py-2">
      <dt className="opacity-55">{label}</dt>
      <dd className="min-w-0 break-all" style={{ color: warn ? "var(--color-critical)" : "inherit" }}>
        {value ?? "—"}
      </dd>
    </div>
  );
}
