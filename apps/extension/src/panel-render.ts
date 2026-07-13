// Pure HTML/text rendering for the Fixly webview report. Deliberately free of
// any `vscode` import so it's unit-testable in a plain Node/vitest environment
// (the vscode-dependent panel wiring lives in panel.ts).
//
// Design: enterprise-dark, restrained. One accent (emerald), flat surfaces,
// 1px hairline borders, uppercase micro-labels, severity shown as dots.
// No gradients, no glows, no emoji, no entry animations.

import {
  buildRemediationPlan,
  computeGrade,
  type Grade,
  type RemediationPlan,
  type ScanGrade,
} from "@fixly/core";
import type { ScanResult, ScanVulnerability, Severity } from "@fixly/core";

/** One line in the guardian's session activity feed (newest first). */
export interface ActivityEvent {
  /** HH:MM:SS */
  at: string;
  kind: "baseline" | "detected" | "escalation" | "remediated" | "failed" | "resolved";
  text: string;
  mttrMs?: number;
}

// Same grade palette as the web ScoreCard (emerald/cyan/yellow/orange/red 400s).
const GRADE_COLORS: Record<Grade, string> = {
  A: "#34d399",
  B: "#22d3ee",
  C: "#facc15",
  D: "#fb923c",
  F: "#f87171",
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#facc15",
  low: "#60a5fa",
  unknown: "#8b8f94",
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];

// The Fixly mark — shield with a bolt, single accent color, no effects.
const LOGO_SVG = `<svg class="logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 2 4 5.4v5.4c0 5 3.4 8.8 8 10.2 4.6-1.4 8-5.2 8-10.2V5.4L12 2Z" stroke="#34d399" stroke-width="1.6" stroke-linejoin="round"/>
  <path d="M13.1 6.8 8.9 12.6h2.6l-1 4.6 4.6-6.2h-2.7l0.7-4.2Z" fill="#34d399"/>
</svg>`;

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

/** Packages / findings stats + a severity distribution bar with legend. */
function overviewHtml(result: ScanResult, counts: Record<Severity, number>): string {
  const total = result.vulnerabilities.length;
  const segments = SEVERITIES.filter((s) => counts[s] > 0)
    .map(
      (s) =>
        `<span class="seg" style="flex:${counts[s]};background:${SEVERITY_COLORS[s]}" title="${counts[s]} ${s}"></span>`
    )
    .join("");
  const bar =
    total > 0
      ? `<div class="sevbar">${segments}</div>`
      : `<div class="sevbar"><span class="seg" style="flex:1;background:rgba(52,211,153,0.4)"></span></div>`;
  const legend = SEVERITIES.filter((s) => counts[s] > 0)
    .map(
      (s) =>
        `<span class="legend-item"><span class="dot" style="background:${SEVERITY_COLORS[s]}"></span>${counts[s]} ${s}</span>`
    )
    .join("");
  return `<section class="panel overview">
    <div class="stat">
      <div class="stat-value">${result.totalPackages}</div>
      <div class="stat-label">Packages</div>
      <div class="muted small">${result.directPackages} direct · ${result.transitivePackages} transitive</div>
    </div>
    <div class="stat">
      <div class="stat-value" style="${total > 0 ? "color:#f87171" : "color:#34d399"}">${total}</div>
      <div class="stat-label">Findings</div>
      <div class="muted small">${result.resolvedPackages} packages checked</div>
    </div>
    <div class="stat dist">
      <div class="stat-label" style="margin-bottom:8px">Severity distribution</div>
      ${bar}
      <div class="legend">${legend || `<span class="legend-item muted">no findings</span>`}</div>
    </div>
  </section>`;
}

function intelTags(v: ScanVulnerability): string {
  const tags: string[] = [];
  if (v.malicious) tags.push(`<span class="tag tag-crit" title="Known malicious package (OSV MAL record)">Malware</span>`);
  if (v.knownExploited) tags.push(`<span class="tag tag-crit" title="CISA Known Exploited Vulnerabilities — confirmed exploitation in the wild">KEV</span>`);
  if (v.pocCount !== null && v.pocCount > 0)
    tags.push(`<span class="tag" title="Public proof-of-concept exploit repos on GitHub">PoC ×${v.pocCount}</span>`);
  if (v.epssScore !== null && v.epssScore >= 0.1)
    tags.push(`<span class="tag" title="EPSS: probability of exploitation in the next 30 days">EPSS ${(v.epssScore * 100).toFixed(0)}%</span>`);
  return tags.length > 0 ? `<div class="tags">${tags.join("")}</div>` : "";
}

function rowHtml(v: ScanVulnerability): string {
  const idCell = v.references[0]
    ? `<a href="${escapeHtml(v.references[0])}">${escapeHtml(v.osvId)}</a>`
    : escapeHtml(v.osvId);
  const cvss = v.cvssScore !== null ? v.cvssScore.toFixed(1) : "—";
  const nvd =
    v.nvd?.cvssScore != null
      ? `<div class="muted small" title="NVD's independent CVSS score for this CVE">NVD ${v.nvd.cvssScore.toFixed(1)}</div>`
      : "";
  const typeChip =
    v.dependencyType === "transitive"
      ? ` <span class="tag" title="Pulled in by another dependency (found in the lock file tree)">transitive</span>`
      : "";
  const sources = escapeHtml(v.sources.join(" · ").toUpperCase());
  const fix = v.fixedVersion
    ? `<span class="fix">→ ${escapeHtml(v.fixedVersion)}</span>`
    : "—";
  return `<tr>
    <td><div class="pkg">${escapeHtml(v.package)}${typeChip}</div><div class="muted mono small">v${escapeHtml(v.installedVersion)}</div></td>
    <td class="mono">${idCell}<div class="muted small">${sources}</div></td>
    <td class="mono muted">${v.cveId ? escapeHtml(v.cveId) : "—"}</td>
    <td><span class="sev"><span class="dot" style="background:${SEVERITY_COLORS[v.severity]}"></span>${escapeHtml(v.severity)}</span>${intelTags(v)}</td>
    <td class="mono">${cvss}${nvd}</td>
    <td class="summary">${escapeHtml(v.title)}</td>
    <td class="mono">${fix}</td>
  </tr>`;
}

const ACTIVITY_LABELS: Record<ActivityEvent["kind"], { label: string; cls: string }> = {
  baseline: { label: "Baseline", cls: "neutral" },
  detected: { label: "Detected", cls: "bad" },
  escalation: { label: "Escalated", cls: "bad" },
  remediated: { label: "Remediated", cls: "good" },
  failed: { label: "Failed", cls: "bad" },
  resolved: { label: "Resolved", cls: "good" },
};

function activityHtml(activity: ActivityEvent[]): string {
  if (activity.length === 0) return "";
  const rows = activity
    .map((e) => {
      const meta = ACTIVITY_LABELS[e.kind];
      const mttr =
        e.mttrMs !== undefined
          ? `<span class="tag tag-good">MTTR ${(e.mttrMs / 1000).toFixed(1)}s</span>`
          : "";
      return `<li class="act"><span class="mono act-time">${escapeHtml(e.at)}</span><span class="act-kind act-${meta.cls}">${meta.label}</span><span class="act-text">${escapeHtml(e.text)}</span>${mttr}</li>`;
    })
    .join("");
  return `<section class="panel">
    <div class="section-title">Guardian activity</div>
    <ul class="activity">${rows}</ul>
  </section>`;
}

function forecastHtml(plan: RemediationPlan): string {
  if (plan.actions.length === 0) return "";
  const { before, after } = plan.forecast;
  return `<div class="forecast">Fix everything → <span style="color:${GRADE_COLORS[after.grade]};font-weight:600">${after.grade} (${after.score}/100)</span><span class="muted"> · currently ${before.grade} (${before.score}/100) · ${plan.actions.length} action${plan.actions.length === 1 ? "" : "s"}</span></div>`;
}

function scoreHtml(grade: ScanGrade, plan: RemediationPlan): string {
  const color = GRADE_COLORS[grade.grade];
  // Static SVG progress ring: r=36 → circumference ≈ 226.2.
  const C = 226.2;
  const dash = (Math.max(0, Math.min(100, grade.score)) / 100) * C;
  const fixes =
    grade.topFixes.length > 0
      ? `<div class="fixes">
          <div class="section-title">Fix these first</div>
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
  return `<section class="panel score">
    <div class="ring-wrap">
      <svg class="ring" viewBox="0 0 84 84">
        <circle cx="42" cy="42" r="36" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="4"/>
        <circle cx="42" cy="42" r="36" fill="none" stroke="${color}" stroke-width="4"
          stroke-linecap="round" stroke-dasharray="${dash} ${C}" transform="rotate(-90 42 42)"/>
      </svg>
      <div class="score-letter" style="color:${color}">${grade.grade}</div>
    </div>
    <div class="score-body">
      <div class="score-title">Fixly Score <span class="mono score-num">${grade.score}<span class="muted">/100</span></span></div>
      <div class="score-headline muted">${escapeHtml(grade.headline)}</div>
      ${forecastHtml(plan)}
      ${fixes}
    </div>
  </section>`;
}

export function renderHtml(
  result: ScanResult,
  nonce: string,
  activity: ActivityEvent[] = []
): string {
  const counts = severityCounts(result);
  const grade = computeGrade(result);
  const plan = buildRemediationPlan(result);
  const fixAllButton =
    plan.actions.length > 0
      ? `<button id="fixall" class="primary">Fix Everything &amp; Verify</button>`
      : "";

  const warningsHtml =
    result.warnings.length > 0 || result.error
      ? `<section class="panel warnings">
          <div class="section-title">Warnings</div>
          <ul>
            ${result.error ? `<li class="err">${escapeHtml(result.error.message)}</li>` : ""}
            ${result.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}
          </ul>
        </section>`
      : "";

  const tableHtml =
    result.vulnerabilities.length > 0
      ? `<section class="panel table-panel">
          <div class="section-title">Findings</div>
          <table>
          <thead>
            <tr>
              <th>Package</th><th>ID</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Summary</th><th>Fix</th>
            </tr>
          </thead>
          <tbody>${result.vulnerabilities.map(rowHtml).join("")}</tbody>
        </table></section>`
      : `<section class="panel clean">No vulnerabilities found across ${result.totalPackages} packages.<div class="muted" style="margin-top:4px">Monitoring for new advisories and dependency changes.</div></section>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: var(--vscode-font-family, system-ui); background: #0A0A0A; color: #E6E6E6; margin: 0; padding: 28px 32px 36px; font-size: 13px; line-height: 1.5; }
  .container { max-width: 940px; margin: 0 auto; }
  .muted { color: #8B8F94; }
  .small { font-size: 10.5px; }
  .mono { font-family: var(--vscode-editor-font-family, ui-monospace, monospace); }

  /* header */
  header { display: flex; align-items: center; gap: 10px; padding-bottom: 16px; margin-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.08); }
  .logo { width: 22px; height: 22px; }
  .wordmark { font-size: 15px; font-weight: 650; letter-spacing: -0.01em; color: #fff; }
  .divider { color: rgba(255,255,255,0.15); }
  .repo-name { font-weight: 500; color: #C9CDD1; }
  .header-meta { margin-left: auto; font-size: 11.5px; color: #8B8F94; }

  /* actions */
  .actions { display: flex; gap: 8px; margin: 18px 0 14px; }
  button { background: transparent; color: #C9CDD1; border: 1px solid rgba(255,255,255,0.14); border-radius: 6px; padding: 6px 14px; font-size: 12px; font-weight: 500; cursor: pointer; }
  button:hover { background: rgba(255,255,255,0.06); }
  button.primary { background: #1f8a5f; color: #fff; border-color: transparent; font-weight: 600; }
  button.primary:hover { background: #23996a; }

  /* shared panel */
  .panel { background: #111214; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 18px 20px; margin: 0 0 12px; }
  .section-title { font-size: 10.5px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: #8B8F94; margin-bottom: 10px; }

  /* score */
  .score { display: flex; gap: 24px; align-items: center; padding: 20px 22px; }
  .ring-wrap { position: relative; width: 84px; height: 84px; flex-shrink: 0; }
  .ring { width: 84px; height: 84px; }
  .score-letter { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 30px; font-weight: 650; letter-spacing: -0.02em; }
  .score-title { font-weight: 600; font-size: 13px; display: flex; align-items: baseline; gap: 8px; }
  .score-num { font-size: 17px; font-weight: 650; font-variant-numeric: tabular-nums; }
  .score-headline { font-size: 12.5px; margin-top: 3px; max-width: 560px; }
  .forecast { font-size: 12px; margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.06); }
  .fixes { margin-top: 12px; }
  .fixes ul { margin: 0; padding-left: 16px; }
  .fixes li { font-size: 12px; margin: 4px 0; }
  .cmd { color: #34d399; font-size: 11px; margin-top: 2px; }

  /* overview */
  .overview { display: grid; grid-template-columns: 1fr 1fr 2.2fr; gap: 28px; align-items: start; }
  .stat-value { font-size: 24px; font-weight: 650; font-variant-numeric: tabular-nums; letter-spacing: -0.01em; line-height: 1.1; }
  .stat-label { font-size: 10.5px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: #8B8F94; margin: 4px 0 2px; }
  .sevbar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; gap: 2px; background: rgba(255,255,255,0.04); }
  .seg { display: block; min-width: 8px; border-radius: 2px; }
  .legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; }
  .legend-item { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; color: #9DA2A8; text-transform: capitalize; }
  .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }

  /* activity */
  .activity { margin: 0; padding: 0; list-style: none; }
  .act { display: flex; gap: 10px; align-items: baseline; font-size: 12px; padding: 5px 0; border-top: 1px solid rgba(255,255,255,0.05); }
  .act:first-child { border-top: 0; }
  .act-time { color: #6E7378; font-size: 11px; flex-shrink: 0; }
  .act-kind { font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; width: 82px; flex-shrink: 0; }
  .act-good { color: #34d399; }
  .act-bad { color: #f87171; }
  .act-neutral { color: #8B8F94; }
  .act-text { color: #C9CDD1; }

  /* tags */
  .tags { margin-top: 5px; display: flex; flex-wrap: wrap; gap: 4px; }
  .tag { display: inline-block; border: 1px solid rgba(255,255,255,0.16); border-radius: 4px; padding: 0 6px; font-size: 10px; font-weight: 500; color: #8B8F94; white-space: nowrap; }
  .tag-crit { color: #f87171; border-color: rgba(248,113,113,0.4); }
  .tag-good { color: #34d399; border-color: rgba(52,211,153,0.4); }

  /* warnings */
  .warnings .section-title { color: #d4a72c; }
  .warnings ul { margin: 0; padding-left: 16px; }
  .warnings li { font-size: 12px; color: #b8a05e; margin: 2px 0; }
  .warnings li.err { color: #f87171; }

  /* table */
  .table-panel { padding: 12px 0 0; }
  .table-panel .section-title { padding: 0 18px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase; color: #8B8F94; font-weight: 600; padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,0.08); }
  th:first-child, td:first-child { padding-left: 18px; }
  th:last-child, td:last-child { padding-right: 18px; }
  td { padding: 10px 12px; border-top: 1px solid rgba(255,255,255,0.05); vertical-align: top; font-size: 12px; }
  tbody tr:hover { background: rgba(255,255,255,0.025); }
  .pkg { font-weight: 600; color: #E6E6E6; }
  .summary { max-width: 360px; color: #9DA2A8; }
  .fix { color: #34d399; }
  a { color: #79A8E8; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .sev { display: inline-flex; align-items: center; gap: 6px; text-transform: capitalize; font-size: 12px; }
  .clean { color: #C9CDD1; }

  footer { margin-top: 16px; font-size: 11px; color: #6E7378; display: flex; gap: 8px; }
</style>
</head>
<body>
  <main class="container">
  <header>
    ${LOGO_SVG}
    <span class="wordmark">Fixly</span>
    <span class="divider">/</span>
    <span class="repo-name">${escapeHtml(result.repo)}</span>
    <span class="header-meta">${result.totalPackages} packages${result.transitivePackages > 0 ? ` · ${result.directPackages} direct · ${result.transitivePackages} transitive` : ""} · ${result.resolvedPackages} checked</span>
  </header>

  <div class="actions">
    ${fixAllButton}
    <button id="rescan">Rescan</button>
    <button id="copy">Copy Summary</button>
    <button id="export">Export JSON</button>
  </div>

  ${scoreHtml(grade, plan)}

  ${activityHtml(activity)}

  ${overviewHtml(result, counts)}

  ${warningsHtml}
  ${tableHtml}

  <footer>
    <span>Scanned ${escapeHtml(result.scannedAt)}</span><span class="divider">·</span>
    <span>${result.source === "osv+nvd" ? "OSV + NVD" : "OSV"}</span><span class="divider">·</span>
    <span>Fixly — detect · remediate · verify</span>
  </footer>
  </main>

  <script nonce="${nonce}">
    const vscodeApi = acquireVsCodeApi();
    const fixAll = document.getElementById("fixall");
    if (fixAll) fixAll.addEventListener("click", () => vscodeApi.postMessage({ type: "fixAll" }));
    document.getElementById("rescan").addEventListener("click", () => vscodeApi.postMessage({ type: "rescan" }));
    document.getElementById("copy").addEventListener("click", () => vscodeApi.postMessage({ type: "copySummary" }));
    document.getElementById("export").addEventListener("click", () => vscodeApi.postMessage({ type: "exportJson" }));
  </script>
</body>
</html>`;
}
