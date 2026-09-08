import { NextRequest, NextResponse } from "next/server";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8000";

/** Server-side proxy for verify / tamper. The browser never reaches FastAPI. */
export async function POST(request: NextRequest) {
  const { caseId, action, seq } = (await request.json()) as {
    caseId?: string;
    action?: "verify" | "tamper";
    seq?: number;
  };

  if (!caseId || !action) {
    return NextResponse.json({ error: "caseId and action are required" }, { status: 400 });
  }

  const path =
    action === "verify"
      ? `/api/v1/cases/${caseId}/evidence/verify`
      : `/api/v1/cases/${caseId}/evidence/tamper?seq=${seq ?? 2}`;

  const res = await fetch(`${API_BASE_URL}${path}`, { method: "POST", cache: "no-store" });
  return NextResponse.json(await res.json(), { status: res.status });
}
