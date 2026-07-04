// `fixly check <pkg>[@version]` — the pre-install trust check. This is the
// same verdict the MCP server hands to AI coding agents; exit codes make it
// scriptable (0 safe / 1 caution / 2 block).

import { checkPackage } from "@fixly/core";
import { bold, dim, gray, verdictBanner } from "../ui";

/** Split "pkg@1.2.3" / "@scope/pkg@1.2.3" / "pkg" into name + version. */
export function parsePackageSpec(spec: string): { name: string; version: string | null } {
  const at = spec.lastIndexOf("@");
  // No "@", or the only "@" is the scope marker at position 0.
  if (at <= 0) return { name: spec, version: null };
  return { name: spec.slice(0, at), version: spec.slice(at + 1) || null };
}

export interface CheckOptions {
  spec: string;
  json: boolean;
}

export async function check(options: CheckOptions): Promise<number> {
  const { name, version } = parsePackageSpec(options.spec);
  const verdict = await checkPackage(name, version);

  if (options.json) {
    process.stdout.write(JSON.stringify(verdict, null, 2) + "\n");
  } else {
    const lines: string[] = [];
    lines.push("");
    lines.push(
      `  ${verdictBanner(verdict.verdict)}  ${bold(verdict.package)}${verdict.evaluatedVersion ? dim(`@${verdict.evaluatedVersion}`) : ""}`
    );
    lines.push("");
    if (verdict.reasons.length > 0) {
      for (const reason of verdict.reasons) lines.push(`  • ${reason}`);
    } else {
      lines.push(`  ${verdict.summary}`);
    }

    const s = verdict.signals;
    const facts: string[] = [];
    if (s.popular) facts.push("curated-popular");
    if (s.ageDays !== null) facts.push(`${s.ageDays}d old`);
    if (s.weeklyDownloads !== null) facts.push(`${s.weeklyDownloads.toLocaleString()} dl/wk`);
    if (s.hasInstallScripts) facts.push("runs install scripts");
    if (s.maxEpss !== null) facts.push(`max EPSS ${(s.maxEpss * 100).toFixed(0)}%`);
    if (facts.length > 0) {
      lines.push("");
      lines.push(`  ${dim(facts.join(" · "))}`);
    }
    for (const w of verdict.warnings) lines.push(`  ${gray(`⚠ ${w}`)}`);
    lines.push("");
    process.stdout.write(lines.join("\n") + "\n");
  }

  return verdict.verdict === "safe" ? 0 : verdict.verdict === "caution" ? 1 : 2;
}
