// Plain-text scan summary for the Copy Summary action — same format the VS
// Code extension's webview copies (panel-render.ts buildSummaryText), so a
// pasted Fixly summary reads identically no matter which surface produced it.
// Server-only: imports the @fixly/core barrel.

import { computeGrade, type ScanResult } from "@fixly/core";

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;

export function buildSummaryText(result: ScanResult): string {
  const counts: Record<string, number> = {};
  for (const s of SEVERITIES) counts[s] = 0;
  for (const v of result.vulnerabilities) counts[v.severity]++;
  const grade = computeGrade(result);

  const lines = [
    `Fixly scan — ${result.repo}`,
    `Fixly Score: ${grade.grade} (${grade.score}/100) — ${grade.headline}`,
    `Scanned: ${result.scannedAt} (source: ${result.source === "osv+nvd" ? "OSV + NVD" : "OSV"})`,
    `Packages: ${result.totalPackages} (${result.directPackages} direct, ${result.transitivePackages} transitive), ${result.resolvedPackages} checked`,
    `Vulnerabilities: ${result.vulnerabilities.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, unknown ${counts.unknown})`,
    "",
  ];
  for (const v of result.vulnerabilities) {
    lines.push(
      `- [${v.severity.toUpperCase()}] ${v.package}@${v.installedVersion}${v.dependencyType === "transitive" ? " (transitive)" : ""} ${v.osvId}${v.cveId ? ` (${v.cveId})` : ""}${v.fixedVersion ? ` → fix ${v.fixedVersion}` : ""}`
    );
  }
  if (result.warnings.length > 0) {
    lines.push("", "Warnings:");
    for (const w of result.warnings) lines.push(`- ${w}`);
  }
  return lines.join("\n");
}
