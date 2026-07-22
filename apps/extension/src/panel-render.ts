// Pure HTML/text rendering for the Fixly webview report. Deliberately free of
// any `vscode` import so it's unit-testable in a plain Node/vitest environment
// (the vscode-dependent panel wiring lives in panel.ts).

import { buildRemediationPlan, computeGrade, type Grade, type ScanGrade } from "@fixly/core";
import type { RemediationPlan, ScanResult, ScanVulnerability, Severity } from "@fixly/core";

// Same grade palette as the web ScoreCard (emerald/cyan/yellow/orange/red 400s).
const GRADE_COLORS: Record<Grade, string> = {
  A: "#34d399",
  B: "#22d3ee",
  C: "#facc15",
  D: "#fb923c",
  F: "#f87171",
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];

function severityCounts(result: ScanResult): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const v of result.vulnerabilities) counts[v.severity]++;
  return counts;
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function buildSummaryText(result: ScanResult): string {
  const counts = severityCounts(result);
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

function cardHtml(label: string, value: number, cls = ""): string {
  return `<div class="card ${cls}"><div class="card-value">${value}</div><div class="card-label">${escapeHtml(label)}</div></div>`;
}

function rowHtml(v: ScanVulnerability): string {
  const idCell = v.references[0]
    ? `<a href="${escapeHtml(v.references[0])}">${escapeHtml(v.osvId)}</a>`
    : escapeHtml(v.osvId);
  const cvss = v.cvssScore !== null ? v.cvssScore.toFixed(1) : "—";
  const nvd =
    v.nvd?.cvssScore != null
      ? `<div class="muted" style="font-size:10px" title="NVD's independent CVSS score for this CVE">NVD ${v.nvd.cvssScore.toFixed(1)}</div>`
      : "";
  const typeChip =
    v.dependencyType === "transitive"
      ? ` <span class="chip" title="Pulled in by another dependency (found in the lock file tree)">transitive</span>`
      : "";
  const sources = escapeHtml(v.sources.join(" · ").toUpperCase());
  const fix = v.fixedVersion
    ? `<span class="fix">→ ${escapeHtml(v.fixedVersion)}</span>`
    : "—";
  return `<tr>
    <td><div class="pkg">${escapeHtml(v.package)}${typeChip}</div><div class="muted mono">v${escapeHtml(v.installedVersion)}</div></td>
    <td class="mono">${idCell}<div class="muted" style="font-size:10px">${sources}</div></td>
    <td class="mono muted">${v.cveId ? escapeHtml(v.cveId) : "—"}</td>
    <td><span class="badge sev-${v.severity}">${escapeHtml(v.severity)}</span></td>
    <td class="mono">${cvss}${nvd}</td>
    <td class="summary">${escapeHtml(v.title)}</td>
    <td class="mono">${fix}</td>
  </tr>`;
}

function scoreHtml(grade: ScanGrade): string {
  const color = GRADE_COLORS[grade.grade];
  const fixes =
    grade.topFixes.length > 0
      ? `<div class="fixes">
          <div class="fixes-title">Fix these first</div>
          <ul>
            ${grade.topFixes
              .map(
                (fix) =>
                  `<li><span class="pkg">${escapeHtml(fix.package)}</span><span class="muted mono">@${escapeHtml(fix.installedVersion)}</span> <span class="muted">— ${escapeHtml(fix.reason)}</span>${fix.command ? `<div class="cmd mono">$ ${escapeHtml(fix.command)}</div>` : ""}</li>`
              )
              .join("")}
          </ul>
        </div>`
      : "";
  return `<div class="score" style="border-color:${color}40">
    <div class="score-letter" style="color:${color};border-color:${color}40">${grade.grade}</div>
    <div class="score-body">
      <div class="score-title">Fixly Score <span class="muted mono">${grade.score}/100</span></div>
      <div class="score-headline muted">${escapeHtml(grade.headline)}</div>
      ${fixes}
    </div>
  </div>`;
}

/** Grade Forecast line + Apply button; empty when nothing is fixable. */
function forecastHtml(plan: RemediationPlan): string {
  if (plan.actions.length === 0) return "";
  const { after, pointsRecovered } = plan.forecast;
  const color = GRADE_COLORS[after.grade];
  const points = pointsRecovered > 0 ? `, +${pointsRecovered} points` : "";
  return `<div class="forecast">
    <span class="forecast-text">Apply the fix plan → <span class="forecast-grade" style="color:${color}">${after.grade} (${after.score})</span>${points}</span>
    <button id="apply">Apply Fix Plan</button>
  </div>`;
}

export function renderHtml(result: ScanResult, nonce: string): string {
  const counts = severityCounts(result);
  const grade = computeGrade(result);
  const plan = buildRemediationPlan(result);

  const warningsHtml =
    result.warnings.length > 0 || result.error
      ? `<div class="warnings">
          <div class="warnings-title">Warnings</div>
          <ul>
            ${result.error ? `<li class="err">${escapeHtml(result.error.message)}</li>` : ""}
            ${result.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}
          </ul>
        </div>`
      : "";

  const tableHtml =
    result.vulnerabilities.length > 0
      ? `<table>
          <thead>
            <tr>
              <th>Package</th><th>ID</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Summary</th><th>Fix</th>
            </tr>
          </thead>
          <tbody>${result.vulnerabilities.map(rowHtml).join("")}</tbody>
        </table>`
      : `<div class="clean">No vulnerabilities found across ${result.totalPackages} packages.</div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style>
  :root { color-scheme: dark; }
  body { font-family: var(--vscode-font-family, system-ui); background: #0A0A0A; color: #fff; margin: 0; padding: 20px; font-size: 13px; }
  h1 { font-size: 16px; margin: 0; }
  .muted { color: #BFC3C7; }
  .mono { font-family: var(--vscode-editor-font-family, ui-monospace, monospace); }
  .sub { color: #BFC3C7; font-size: 12px; margin-top: 4px; }
  .actions { display: flex; gap: 8px; margin: 16px 0; flex-wrap: wrap; }
  button { background: #fff; color: #0A0A0A; border: 0; border-radius: 6px; padding: 6px 12px; font-size: 12px; font-weight: 600; cursor: pointer; }
  button.secondary { background: #1A1A1A; color: #fff; border: 1px solid rgba(209,213,219,0.2); }
  .cards { display: grid; grid-template-columns: repeat(7, 1fr); gap: 8px; margin: 16px 0; }
  .card { background: #1A1A1A; border: 1px solid rgba(209,213,219,0.1); border-radius: 10px; padding: 12px; }
  .card-value { font-size: 20px; font-weight: 600; }
  .card-label { font-size: 11px; color: #BFC3C7; margin-top: 2px; }
  .score { display: flex; gap: 16px; background: #1A1A1A; border: 1px solid rgba(209,213,219,0.1); border-radius: 10px; padding: 16px; margin: 16px 0; }
  .score-letter { display: flex; align-items: center; justify-content: center; width: 56px; height: 56px; flex-shrink: 0; background: #0A0A0A; border: 1px solid rgba(209,213,219,0.1); border-radius: 10px; font-size: 32px; font-weight: 700; }
  .score-title { font-weight: 600; }
  .score-headline { font-size: 12px; margin-top: 2px; }
  .fixes { margin-top: 10px; }
  .fixes-title { font-size: 11px; font-weight: 600; margin-bottom: 4px; }
  .fixes ul { margin: 0; padding-left: 16px; }
  .fixes li { font-size: 12px; margin: 4px 0; }
  .forecast { display: flex; align-items: center; justify-content: space-between; gap: 12px; background: #1A1A1A; border: 1px solid rgba(209,213,219,0.1); border-radius: 10px; padding: 10px 16px; margin: 0 0 16px; }
  .forecast-text { font-size: 12px; color: #BFC3C7; }
  .forecast-grade { font-weight: 700; }
  .cmd { color: #34d399; background: #0A0A0A; border-radius: 4px; padding: 2px 6px; margin-top: 2px; width: fit-content; font-size: 11px; }
  .warnings { background: rgba(120,90,0,0.12); border: 1px solid rgba(180,140,0,0.4); border-radius: 10px; padding: 12px 14px; margin: 16px 0; }
  .warnings-title { font-size: 11px; font-weight: 600; color: #f4c150; margin-bottom: 6px; }
  .warnings ul { margin: 0; padding-left: 16px; }
  .warnings li { font-size: 12px; color: #e7d6a8; margin: 2px 0; }
  .warnings li.err { color: #f87171; }
  table { width: 100%; border-collapse: collapse; background: #1A1A1A; border: 1px solid rgba(209,213,219,0.1); border-radius: 10px; overflow: hidden; }
  th { text-align: left; font-size: 11px; color: #BFC3C7; padding: 10px 12px; border-bottom: 1px solid rgba(209,213,219,0.1); }
  td { padding: 10px 12px; border-top: 1px solid rgba(209,213,219,0.08); vertical-align: top; }
  .pkg { font-weight: 600; }
  .summary { max-width: 360px; color: #BFC3C7; }
  .fix { color: #34d399; }
  a { color: #BFC3C7; }
  .clean { background: #1A1A1A; border: 1px solid rgba(209,213,219,0.1); border-radius: 10px; padding: 28px; text-align: center; color: #BFC3C7; }
  .chip { display: inline-block; border: 1px solid rgba(209,213,219,0.25); border-radius: 4px; padding: 0 4px; font-size: 10px; font-weight: 400; color: #BFC3C7; vertical-align: middle; }
  .badge { display: inline-block; border-radius: 999px; padding: 1px 8px; font-size: 11px; font-weight: 600; text-transform: capitalize; }
  .sev-critical { background: #450a0a; color: #f87171; }
  .sev-high { background: #431407; color: #fb923c; }
  .sev-medium { background: #422006; color: #facc15; }
  .sev-low { background: #172554; color: #60a5fa; }
  .sev-unknown { background: #1A1A1A; color: #BFC3C7; border: 1px solid rgba(209,213,219,0.2); }
</style>
</head>
<body>
  <h1>${escapeHtml(result.repo)}</h1>
  <div class="sub">${result.totalPackages} packages${result.transitivePackages > 0 ? ` (${result.directPackages} direct + ${result.transitivePackages} transitive)` : ""} · ${result.resolvedPackages} checked${result.target.branch ? ` · branch ${escapeHtml(result.target.branch)}` : ""} · ${escapeHtml(result.scannedAt)} · ${result.source === "osv+nvd" ? "OSV + NVD" : "OSV"}</div>
  ${result.target.filesFound.length ? `<div class="sub">files: ${escapeHtml(result.target.filesFound.join(", "))}${result.target.filesMissing.length ? ` · missing: ${escapeHtml(result.target.filesMissing.join(", "))}` : ""}</div>` : ""}

  <div class="actions">
    <button id="rescan">Rescan Project</button>
    <button id="copy" class="secondary">Copy Summary</button>
    <button id="export" class="secondary">Export JSON Report</button>
  </div>

  ${scoreHtml(grade)}
  ${forecastHtml(plan)}

  <div class="cards">
    ${cardHtml("Packages", result.totalPackages)}
    ${cardHtml("Vulnerabilities", result.vulnerabilities.length)}
    ${SEVERITIES.map((s) => cardHtml(s, counts[s])).join("")}
  </div>

  ${warningsHtml}
  ${tableHtml}

  <script nonce="${nonce}">
    const vscodeApi = acquireVsCodeApi();
    document.getElementById("rescan").addEventListener("click", () => vscodeApi.postMessage({ type: "rescan" }));
    document.getElementById("copy").addEventListener("click", () => vscodeApi.postMessage({ type: "copySummary" }));
    document.getElementById("export").addEventListener("click", () => vscodeApi.postMessage({ type: "exportJson" }));
    document.getElementById("apply")?.addEventListener("click", () => vscodeApi.postMessage({ type: "applyPlan" }));
  </script>
</body>
</html>`;
}
