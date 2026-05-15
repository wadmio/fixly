import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scan";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const repoUrl = typeof body?.repoUrl === "string" ? body.repoUrl.trim() : "";

    if (!repoUrl) {
      return NextResponse.json(
        { error: "repoUrl is required" },
        { status: 400 }
      );
    }

    const result = await runScan(repoUrl);
    return NextResponse.json(result);
  } catch (err) {
    console.error("[/api/scan]", err);
    return NextResponse.json(
      { error: "Internal scan error" },
      { status: 500 }
    );
  }
}
