import { NextRequest, NextResponse } from "next/server";
import { runScan, type ScanErrorCode } from "@fixly/core";

const ERROR_STATUS: Record<ScanErrorCode, number> = {
  invalid_url: 400,
  repo_not_found: 404,
  private_repo: 403,
  branch_not_found: 404,
  no_package_json: 422,
  no_dependencies: 422,
  rate_limited: 429,
  osv_failed: 502,
  github_error: 502,
};

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const repoUrl = typeof body?.repoUrl === "string" ? body.repoUrl.trim() : "";

    if (!repoUrl) {
      // Same { error: { code, message } } shape as a failed ScanResult, so
      // consumers can parse errors uniformly.
      return NextResponse.json(
        { error: { code: "invalid_url", message: "repoUrl is required" } },
        { status: 400 }
      );
    }

    const result = await runScan(repoUrl);

    if (result.error) {
      return NextResponse.json(result, {
        status: ERROR_STATUS[result.error.code] ?? 400,
      });
    }

    return NextResponse.json(result);
  } catch (err) {
    console.error("[/api/scan]", err);
    return NextResponse.json(
      { error: { code: "internal_error", message: "Internal scan error" } },
      { status: 500 }
    );
  }
}
