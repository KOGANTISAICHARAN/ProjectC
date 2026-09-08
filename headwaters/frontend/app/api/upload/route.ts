import { NextRequest, NextResponse } from "next/server";
import { uploadEml } from "@/lib/api";

/** Server-side proxy: the browser never reaches FastAPI directly. */
export async function POST(request: NextRequest) {
  const form = await request.formData();
  const file = form.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json({ error: "No file supplied" }, { status: 400 });
  }
  const result = await uploadEml(file);
  if (!result?.case_id) {
    return NextResponse.json({ error: "Analysis failed" }, { status: 502 });
  }
  return NextResponse.json(result);
}
