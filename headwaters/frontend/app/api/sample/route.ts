import { readFile } from "node:fs/promises";
import path from "node:path";
import { NextRequest, NextResponse } from "next/server";
import { uploadEml } from "@/lib/api";

const ALLOWED = new Set(["bec", "credential_phish", "benign", "malformed"]);

/**
 * Load one of the bundled synthetic fixtures.
 *
 * The name is checked against an allowlist rather than sanitised: this handler
 * reads from disk by name, and an allowlist is the only path-traversal defence
 * that cannot be talked around.
 */
export async function POST(request: NextRequest) {
  const { name } = (await request.json()) as { name?: string };
  if (!name || !ALLOWED.has(name)) {
    return NextResponse.json({ error: "Unknown sample" }, { status: 400 });
  }

  const file = path.join(process.cwd(), "fixtures", `${name}.eml`);
  let bytes: Buffer;
  try {
    bytes = await readFile(file);
  } catch {
    return NextResponse.json(
      { error: `Sample '${name}' is not bundled with this build` },
      { status: 404 },
    );
  }

  const result = await uploadEml(
    new File([new Uint8Array(bytes)], `${name}.eml`, { type: "message/rfc822" }),
  );
  if (!result?.case_id) {
    return NextResponse.json({ error: "Analysis failed" }, { status: 502 });
  }
  return NextResponse.json(result);
}
