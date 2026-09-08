import { NextRequest, NextResponse } from "next/server";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8000";

/** Generate a report and return its download path. */
export async function POST(request: NextRequest) {
  const { caseId } = (await request.json()) as { caseId?: string };
  if (!caseId) {
    return NextResponse.json({ error: "caseId is required" }, { status: 400 });
  }
  const res = await fetch(`${API_BASE_URL}/api/v1/cases/${caseId}/reports`, {
    method: "POST",
    cache: "no-store",
  });
  return NextResponse.json(await res.json(), { status: res.status });
}
