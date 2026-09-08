/**
 * Server-side API client.
 *
 * Imported only from Server Components and route handlers. `API_BASE_URL` has
 * no NEXT_PUBLIC_ prefix, so the browser never talks to FastAPI directly and no
 * upstream URL or credential can reach the client bundle.
 */

import "server-only";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8000";
const TIMEOUT_MS = 15_000;

export interface ApiHealth {
  reachable: boolean;
  environment: string | null;
  database: boolean | null;
  databaseApp: boolean | null;
}

export interface CaseSummary {
  id: string;
  case_ref: string;
  status: string;
  score: number | null;
  band: string | null;
  classification: string | null;
  data_completeness: number | null;
  subject: string | null;
  from_address: string | null;
  created_at: string;
}

export interface Hop {
  seq: number;
  helo: string | null;
  rdns_claim: string | null;
  observed_ip: string | null;
  by_host: string | null;
  ip_class: string;
  role: string;
  trust_state: string;
  hop_ts_utc: string | null;
  anomalies: string[];
  asn: number | null;
  asn_org: string | null;
  country: string | null;
  net_type: string | null;
}

export interface Finding {
  signal_group: string;
  rule_id: string;
  severity: string;
  title: string;
  /** One sentence for a non-specialist. Shown first. */
  plain_summary: string | null;
  /** The precise technical account. Kept one click away. */
  detail: string | null;
  score_contribution: number;
  evidence_ref: string | null;
  evidence_quote: string | null;
  mitre_technique: string | null;
}

export interface AuthResult {
  mechanism: string;
  result_reported: string | null;
  authserv_id: string | null;
  trusted_source: boolean;
  aligned: boolean | null;
  d_domain: string | null;
  caveat: string | null;
}

export interface Origin {
  feos_ip: string | null;
  boundary_hop_seq: number | null;
  confidence: number;
  confidence_breakdown: Record<string, number>;
  claim_text: string | null;
  geo_dataset: string | null;
  geo_available: boolean;
}

export interface CaseDetail extends CaseSummary {
  weights_version: string | null;
  reply_to: string | null;
  return_path: string | null;
  message_id: string | null;
  hops: Hop[];
  findings: Finding[];
  auth_results: AuthResult[];
  origin: Origin | null;
  group_contributions: Record<string, number>;
  urls: string[];
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      signal: controller.signal,
      cache: "no-store",
      headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    });
    return (await res.json()) as T;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function getApiHealth(): Promise<ApiHealth> {
  const [health, ready] = await Promise.all([
    fetchJson<{ environment: string }>("/healthz"),
    fetchJson<{ checks: { database: boolean; database_app: boolean } }>("/readyz"),
  ]);
  return {
    reachable: health !== null,
    environment: health?.environment ?? null,
    database: ready?.checks?.database ?? null,
    databaseApp: ready?.checks?.database_app ?? null,
  };
}

export async function listCases(): Promise<CaseSummary[]> {
  return (await fetchJson<CaseSummary[]>("/api/v1/cases")) ?? [];
}

export interface EvidenceEvent {
  seq: number;
  ts_utc: string;
  actor: string;
  action: string;
  payload_hash: string;
  prev_hash: string | null;
  entry_hash: string;
  signing_key_id: string | null;
}

export interface CampaignMember {
  case_id: string;
  case_ref: string;
  score: number | null;
  dna_score: number;
  locus_breakdown: Record<string, number>;
  shared_indicators: string[];
}

export interface Campaign {
  id: string;
  name: string;
  summary: string | null;
  member_count: number;
  max_score: number | null;
  first_seen: string | null;
  last_seen: string | null;
  barcode: string | null;
  members: CampaignMember[];
  caveat: string;
}

export interface GraphNode {
  data: {
    id: string;
    label: string;
    kind: string;
    root?: boolean;
    hub?: boolean;
    score?: number | null;
    band?: string | null;
    members?: number;
  };
}

export interface GraphEdge {
  data: { source: string; target: string; type: string; weight?: number };
}

export interface CaseGraph {
  elements: { nodes: GraphNode[]; edges: GraphEdge[] };
  hub_values_suppressed: string[];
  note: string;
}

export interface TimelineEntry {
  at: string;
  kind: string;
  title: string;
  detail: string;
  trust: string;
  seq?: number;
}

export interface CaseTimeline {
  entries: TimelineEntry[];
  legend: Record<string, string>;
}

export async function getGraph(id: string): Promise<CaseGraph | null> {
  const g = await fetchJson<CaseGraph>(`/api/v1/cases/${id}/graph`);
  return g && "elements" in g ? g : null;
}

export async function getTimeline(id: string): Promise<CaseTimeline | null> {
  const t = await fetchJson<CaseTimeline>(`/api/v1/cases/${id}/timeline`);
  return t && "entries" in t ? t : null;
}

export async function getCampaign(id: string): Promise<Campaign | null> {
  const c = await fetchJson<Campaign | null>(`/api/v1/cases/${id}/campaign`);
  return c && "name" in c ? c : null;
}

export async function getEvidence(id: string): Promise<EvidenceEvent[]> {
  return (await fetchJson<EvidenceEvent[]>(`/api/v1/cases/${id}/evidence`)) ?? [];
}

export async function getCase(id: string): Promise<CaseDetail | null> {
  const detail = await fetchJson<CaseDetail>(`/api/v1/cases/${id}`);
  return detail && "id" in detail ? detail : null;
}

/** Forwards an uploaded .eml to the API. Called from a route handler. */
export async function uploadEml(file: File): Promise<{ case_id?: string } | null> {
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(`${API_BASE_URL}/api/v1/cases`, { method: "POST", body });
  return (await res.json()) as { case_id?: string };
}

export const SAMPLES = [
  { key: "bec", label: "CEO impersonation (BEC)", hint: "every auth check passes" },
  { key: "credential_phish", label: "Credential phishing", hint: "SPF fail, fake helpdesk" },
  { key: "benign", label: "Legitimate newsletter", hint: "the false-positive guard" },
  { key: "malformed", label: "Malformed / hostile MIME", hint: "must fail safely" },
] as const;
