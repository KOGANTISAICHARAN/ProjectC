import { NextRequest } from "next/server";

const API_BASE_URL = process.env.API_BASE_URL ?? "http://localhost:8000";

/**
 * Serve a generated report through the dashboard's own origin.
 *
 * The case page links here rather than to the API directly, because
 * `API_BASE_URL` is server-side only -- the browser has no way to build the
 * upstream URL. Without this route the link resolved to a Next.js page that does
 * not exist, and the browser rendered an internal payload the reader cannot use.
 *
 * The upstream body streams through unchanged so a PDF stays a PDF; only the
 * headers describing it are forwarded.
 */
export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const upstream = await fetch(`${API_BASE_URL}/api/v1/reports/${id}`, {
    cache: "no-store",
  });

  if (!upstream.ok) {
    return new Response("Report not found", { status: upstream.status });
  }

  const headers = new Headers();
  for (const name of [
    "content-type",
    "content-disposition",
    "x-report-format",
    "x-report-sha256",
  ]) {
    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }

  return new Response(upstream.body, { status: 200, headers });
}
