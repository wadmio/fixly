// Pure HTML/text rendering for the Fixly webview report. Deliberately free of
// any `vscode` import so it's unit-testable in a plain Node/vitest environment
// (the vscode-dependent panel wiring lives in panel.ts).

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
  unknown: "#9ca3af",
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];

// The Fixly mark: a shield with a lightning bolt — detection with teeth.
const LOGO_SVG = `<svg class="logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <defs>
    <linearGradient id="fxg" x1="0" y1="0" x2="24" y2="24">
      <stop offset="0" stop-color="#34d399"/><stop offset="1" stop-color="#22d3ee"/>
    </linearGradient>
  </defs>
  <path d="M12 2 4 5.4v5.4c0 5 3.4 8.8 8 10.2 4.6-1.4 8-5.2 8-10.2V5.4L12 2Z" stroke="url(#fxg)" stroke-width="1.6" stroke-linejoin="round"/>
  <path d="M13.1 6.8 8.9 12.6h2.6l-1 4.6 4.6-6.2h-2.7l0.7-4.2Z" fill="url(#fxg)"/>
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

function cardHtml(label: string, value: number, accent: string): string {
  return `<div class="card" style="--accent:${accent}"><div class="card-value">${value}</div><div class="card-label">${escapeHtml(label)}</div></div>`;
}

function intelChips(v: ScanVulnerability): string {
  const chips: string[] = [];
  if (v.malicious) chips.push(`<span class="ichip mal" title="Known malicious package (OSV MAL record)">☠ MALICIOUS</span>`);
  if (v.knownExploited) chips.push(`<span class="ichip kev" title="In CISA's Known Exploited Vulnerabilities catalog — confirmed exploitation in the wild">⚡ exploited in the wild</span>`);
  if (v.pocCount !== null && v.pocCount > 0)
    chips.push(`<span class="ichip poc" title="Public proof-of-concept exploit repos on GitHub">PoC ×${v.pocCount}</span>`);
  if (v.epssScore !== null && v.epssScore >= 0.1)
    chips.push(`<span class="ichip epss" title="EPSS: probability of exploitation in the next 30 days">EPSS ${(v.epssScore * 100).toFixed(0)}%</span>`);
  return chips.length > 0 ? `<div class="ichips">${chips.join("")}</div>` : "";
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
    <td><span class="badge sev-${v.severity}">${escapeHtml(v.severity)}</span>${intelChips(v)}</td>
    <td class="mono">${cvss}${nvd}</td>
    <td class="summary">${escapeHtml(v.title)}</td>
    <td class="mono">${fix}</td>
  </tr>`;
}

const ACTIVITY_GLYPHS: Record<ActivityEvent["kind"], string> = {
  baseline: "◎",
  detected: "✖",
  escalation: "‼",
  remediated: "✔",
  failed: "✖",
  resolved: "−",
};

function activityHtml(activity: ActivityEvent[]): string {
  if (activity.length === 0) return "";
  const rows = activity
    .map((e, i) => {
      const mttr =
        e.mttrMs !== undefined
          ? ` <span class="mttr">⚡ MTTR ${(e.mttrMs / 1000).toFixed(1)}s</span>`
          : "";
      return `<li class="act act-${e.kind}" style="animation-delay:${Math.min(i * 60, 400)}ms"><span class="act-dot"></span><span class="act-glyph">${ACTIVITY_GLYPHS[e.kind]}</span><span class="mono act-time">${escapeHtml(e.at)}</span><span class="act-text">${escapeHtml(e.text)}${mttr}</span></li>`;
    })
    .join("");
  return `<div class="feed rise" style="animation-delay:120ms">
    <div class="section-title">Guardian activity <span class="muted">— this session, newest first</span></div>
    <ul class="timeline">${rows}</ul>
  </div>`;
}

function forecastHtml(plan: RemediationPlan): string {
  if (plan.actions.length === 0) return "";
  const { before, after } = plan.forecast;
  return `<div class="forecast">Fix everything → <span class="forecast-grade" style="color:${GRADE_COLORS[after.grade]}">${after.grade} (${after.score}/100)</span> <span class="muted">from ${before.grade} (${before.score}/100) · ${plan.actions.length} action${plan.actions.length === 1 ? "" : "s"}</span></div>`;
}

function scoreHtml(grade: ScanGrade, plan: RemediationPlan): string {
  const color = GRADE_COLORS[grade.grade];
  // SVG progress ring: r=46 → circumference ≈ 289.
  const C = 289;
  const dash = Math.max(0, Math.min(100, grade.score)) * (C / 100);
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
  return `<div class="score rise" style="--grade:${color}">
    <div class="ring-wrap">
      <svg class="ring" viewBox="0 0 110 110">
        <circle cx="55" cy="55" r="46" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="7"/>
        <circle class="ring-fill" cx="55" cy="55" r="46" fill="none" stroke="${color}" stroke-width="7"
          stroke-linecap="round" stroke-dasharray="${dash} ${C}" transform="rotate(-90 55 55)"/>
      </svg>
      <div class="score-letter" style="color:${color};text-shadow:0 0 32px ${color}88">${grade.grade}</div>
    </div>
    <div class="score-body">
      <div class="score-title">Fixly Score <span class="score-num mono" style="color:${color}">${grade.score}<span class="muted">/100</span></span></div>
      <div class="score-headline muted">${escapeHtml(grade.headline)}</div>
      ${forecastHtml(plan)}
      ${fixes}
    </div>
  </div>`;
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
      ? `<button id="fixall" class="primary">⚡ Fix Everything &amp; Verify → ${plan.forecast.after.grade} (${plan.forecast.after.score})</button>`
      : "";

  const warningsHtml =
    result.warnings.length > 0 || result.error
      ? `<div class="warnings rise">
          <div class="warnings-title">Warnings</div>
          <ul>
            ${result.error ? `<li class="err">${escapeHtml(result.error.message)}</li>` : ""}
            ${result.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}
          </ul>
        </div>`
      : "";

  const tableHtml =
    result.vulnerabilities.length > 0
      ? `<table class="rise" style="animation-delay:180ms">
          <thead>
            <tr>
              <th>Package</th><th>ID</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Summary</th><th>Fix</th>
            </tr>
          </thead>
          <tbody>${result.vulnerabilities.map(rowHtml).join("")}</tbody>
        </table>`
      : `<div class="clean rise" style="animation-delay:180ms"><div class="clean-mark">✔</div>No vulnerabilities found across ${result.totalPackages} packages.<div class="muted" style="margin-top:4px">The guardian is watching — new advisories and dependency changes are remediated automatically.</div></div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    font-family: var(--vscode-font-family, system-ui);
    background:
      radial-gradient(1200px 500px at 80% -10%, rgba(52,211,153,0.07), transparent 60%),
      radial-gradient(900px 400px at -10% 0%, rgba(34,211,238,0.06), transparent 55%),
      #0A0A0A;
    color: #fff; margin: 0; padding: 24px; font-size: 13px;
  }
  .muted { color: #9aa0a6; }
  .mono { font-family: var(--vscode-editor-font-family, ui-monospace, monospace); }

  @keyframes riseIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
  .rise { animation: riseIn 420ms cubic-bezier(0.22,1,0.36,1) both; }

  /* ---- brand header ---- */
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
  .logo { width: 28px; height: 28px; filter: drop-shadow(0 0 10px rgba(52,211,153,0.45)); }
  .wordmark { font-size: 20px; font-weight: 800; letter-spacing: -0.02em;
    background: linear-gradient(90deg, #34d399, #22d3ee); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .tagline { font-size: 11px; color: #9aa0a6; border: 1px solid rgba(255,255,255,0.1); border-radius: 999px; padding: 2px 10px; letter-spacing: 0.06em; text-transform: uppercase; }
  .repo-line { margin-left: auto; text-align: right; }
  .repo-name { font-weight: 700; font-size: 14px; }
  .sub { color: #9aa0a6; font-size: 11.5px; margin-top: 2px; }

  /* ---- actions ---- */
  .actions { display: flex; gap: 8px; margin: 18px 0; flex-wrap: wrap; }
  button { background: rgba(255,255,255,0.06); color: #fff; border: 1px solid rgba(255,255,255,0.12); border-radius: 8px; padding: 7px 14px; font-size: 12px; font-weight: 600; cursor: pointer; transition: transform 120ms ease, box-shadow 120ms ease, background 120ms ease; }
  button:hover { transform: translateY(-1px); background: rgba(255,255,255,0.1); }
  button.primary { background: linear-gradient(90deg, #34d399, #22d3ee); color: #04150d; border: 0; box-shadow: 0 4px 24px rgba(52,211,153,0.35); }
  button.primary:hover { box-shadow: 0 6px 32px rgba(52,211,153,0.5); }
  button.secondary { background: rgba(255,255,255,0.04); }

  /* ---- score hero ---- */
  .score { display: flex; gap: 22px; align-items: center;
    background: linear-gradient(180deg, rgba(255,255,255,0.045), rgba(255,255,255,0.015));
    border: 1px solid color-mix(in srgb, var(--grade) 28%, transparent);
    box-shadow: 0 0 60px color-mix(in srgb, var(--grade) 10%, transparent), inset 0 1px 0 rgba(255,255,255,0.06);
    border-radius: 16px; padding: 20px 24px; margin: 16px 0; }
  .ring-wrap { position: relative; width: 110px; height: 110px; flex-shrink: 0; }
  .ring { width: 110px; height: 110px; }
  @keyframes ringIn { from { stroke-dasharray: 0 289; } }
  .ring-fill { animation: ringIn 900ms cubic-bezier(0.22,1,0.36,1) both; filter: drop-shadow(0 0 6px currentColor); }
  @keyframes pop { 0% { transform: translate(-50%,-50%) scale(0.6); opacity: 0; } 60% { transform: translate(-50%,-50%) scale(1.12); } 100% { transform: translate(-50%,-50%) scale(1); opacity: 1; } }
  .score-letter { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
    font-size: 46px; font-weight: 800; letter-spacing: -0.03em; animation: pop 600ms 250ms cubic-bezier(0.22,1,0.36,1) both; }
  .score-title { font-weight: 700; font-size: 14px; display: flex; align-items: baseline; gap: 8px; }
  .score-num { font-size: 22px; font-weight: 800; }
  .score-headline { font-size: 12.5px; margin-top: 3px; }
  .forecast { font-size: 12.5px; margin-top: 10px; font-weight: 600; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.09); border-radius: 999px; padding: 5px 12px; width: fit-content; }
  .forecast-grade { font-weight: 800; }
  .fixes { margin-top: 12px; }
  .fixes-title { font-size: 10.5px; font-weight: 700; margin-bottom: 4px; letter-spacing: 0.08em; text-transform: uppercase; color: #9aa0a6; }
  .fixes ul { margin: 0; padding-left: 16px; }
  .fixes li { font-size: 12px; margin: 5px 0; }
  .cmd { color: #34d399; background: rgba(52,211,153,0.08); border: 1px solid rgba(52,211,153,0.2); border-radius: 6px; padding: 2px 8px; margin-top: 3px; width: fit-content; font-size: 11px; }

  /* ---- stat cards ---- */
  .cards { display: grid; grid-template-columns: repeat(7, 1fr); gap: 8px; margin: 16px 0; }
  .card { position: relative; overflow: hidden; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 12px 12px 10px; }
  .card::before { content: ""; position: absolute; inset: 0 auto auto 0; width: 100%; height: 2px; background: var(--accent, rgba(255,255,255,0.15)); opacity: 0.85; }
  .card-value { font-size: 22px; font-weight: 800; }
  .card-label { font-size: 10.5px; color: #9aa0a6; margin-top: 2px; text-transform: capitalize; }

  /* ---- guardian feed (timeline) ---- */
  .feed { background: rgba(255,255,255,0.025); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 14px 18px; margin: 16px 0; }
  .section-title { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #cbd0d6; margin-bottom: 10px; }
  .timeline { margin: 0; padding: 0 0 0 6px; list-style: none; position: relative; }
  .timeline::before { content: ""; position: absolute; left: 9px; top: 6px; bottom: 6px; width: 1px; background: linear-gradient(180deg, rgba(52,211,153,0.5), rgba(255,255,255,0.06)); }
  .act { position: relative; display: flex; gap: 8px; align-items: baseline; font-size: 12.5px; margin: 8px 0; padding-left: 18px; animation: riseIn 360ms cubic-bezier(0.22,1,0.36,1) both; }
  .act-dot { position: absolute; left: 0; top: 3px; width: 7px; height: 7px; border-radius: 50%; background: #9aa0a6; box-shadow: 0 0 0 3px rgba(255,255,255,0.05); }
  .act-remediated .act-dot, .act-resolved .act-dot { background: #34d399; box-shadow: 0 0 10px rgba(52,211,153,0.7); }
  .act-detected .act-dot, .act-failed .act-dot, .act-escalation .act-dot { background: #f87171; box-shadow: 0 0 10px rgba(248,113,113,0.6); }
  .act-glyph { width: 14px; text-align: center; }
  .act-remediated .act-glyph, .act-resolved .act-glyph { color: #34d399; }
  .act-detected .act-glyph, .act-failed .act-glyph, .act-escalation .act-glyph { color: #f87171; }
  .act-time { color: #6b7280; font-size: 11px; }
  .act-text { color: #e5e7eb; }
  .mttr { background: linear-gradient(90deg, rgba(52,211,153,0.18), rgba(34,211,238,0.14)); color: #34d399; border: 1px solid rgba(52,211,153,0.35); border-radius: 999px; padding: 1px 9px; font-size: 10.5px; font-weight: 800; margin-left: 6px; white-space: nowrap; }

  /* ---- warnings ---- */
  .warnings { background: rgba(120,90,0,0.1); border: 1px solid rgba(180,140,0,0.35); border-radius: 12px; padding: 12px 14px; margin: 16px 0; }
  .warnings-title { font-size: 10.5px; font-weight: 700; color: #f4c150; margin-bottom: 6px; letter-spacing: 0.08em; text-transform: uppercase; }
  .warnings ul { margin: 0; padding-left: 16px; }
  .warnings li { font-size: 12px; color: #e7d6a8; margin: 2px 0; }
  .warnings li.err { color: #f87171; }

  /* ---- findings table ---- */
  table { width: 100%; border-collapse: collapse; background: rgba(255,255,255,0.025); border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; overflow: hidden; }
  th { text-align: left; font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase; color: #9aa0a6; padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.02); }
  td { padding: 10px 12px; border-top: 1px solid rgba(255,255,255,0.05); vertical-align: top; }
  tbody tr { transition: background 120ms ease; }
  tbody tr:hover { background: rgba(255,255,255,0.035); }
  .pkg { font-weight: 700; }
  .summary { max-width: 360px; color: #b9bec5; }
  .fix { color: #34d399; font-weight: 600; }
  a { color: #8ab4f8; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .clean { background: rgba(52,211,153,0.05); border: 1px solid rgba(52,211,153,0.25); border-radius: 14px; padding: 30px; text-align: center; color: #c7cdd3; }
  .clean-mark { font-size: 26px; color: #34d399; margin-bottom: 6px; text-shadow: 0 0 18px rgba(52,211,153,0.7); }
  .chip { display: inline-block; border: 1px solid rgba(255,255,255,0.2); border-radius: 4px; padding: 0 4px; font-size: 10px; font-weight: 400; color: #9aa0a6; vertical-align: middle; }
  .badge { display: inline-block; border-radius: 999px; padding: 1px 9px; font-size: 11px; font-weight: 700; text-transform: capitalize; }
  .sev-critical { background: rgba(248,113,113,0.14); color: #f87171; border: 1px solid rgba(248,113,113,0.35); }
  .sev-high { background: rgba(251,146,60,0.12); color: #fb923c; border: 1px solid rgba(251,146,60,0.3); }
  .sev-medium { background: rgba(250,204,21,0.1); color: #facc15; border: 1px solid rgba(250,204,21,0.25); }
  .sev-low { background: rgba(96,165,250,0.1); color: #60a5fa; border: 1px solid rgba(96,165,250,0.25); }
  .sev-unknown { background: rgba(255,255,255,0.05); color: #9aa0a6; border: 1px solid rgba(255,255,255,0.15); }
  .ichips { margin-top: 5px; display: flex; flex-wrap: wrap; gap: 4px; }
  .ichip { border-radius: 999px; padding: 0 7px; font-size: 10px; font-weight: 700; white-space: nowrap; }
  .ichip.kev { background: rgba(248,113,113,0.14); color: #f87171; border: 1px solid rgba(248,113,113,0.4); }
  .ichip.mal { background: #450a0a; color: #fecaca; border: 1px solid #f87171; }
  .ichip.poc { background: rgba(251,146,60,0.12); color: #fb923c; border: 1px solid rgba(251,146,60,0.35); }
  .ichip.epss { background: rgba(250,204,21,0.1); color: #facc15; border: 1px solid rgba(250,204,21,0.3); }

  .footer { margin-top: 22px; text-align: center; font-size: 11px; color: #6b7280; }
  .footer b { background: linear-gradient(90deg, #34d399, #22d3ee); -webkit-background-clip: text; background-clip: text; color: transparent; }
</style>
</head>
<body>
  <div class="brand rise">
    ${LOGO_SVG}
    <span class="wordmark">fixly</span>
    <span class="tagline">real-time remediation</span>
    <div class="repo-line">
      <div class="repo-name">${escapeHtml(result.repo)}</div>
      <div class="sub">${result.totalPackages} packages${result.transitivePackages > 0 ? ` (${result.directPackages} direct + ${result.transitivePackages} transitive)` : ""} · ${result.resolvedPackages} checked · ${result.source === "osv+nvd" ? "OSV + NVD" : "OSV"}</div>
    </div>
  </div>

  <div class="actions rise" style="animation-delay:60ms">
    ${fixAllButton}
    <button id="rescan" class="secondary">Rescan</button>
    <button id="copy" class="secondary">Copy Summary</button>
    <button id="export" class="secondary">Export JSON</button>
  </div>

  ${scoreHtml(grade, plan)}

  ${activityHtml(activity)}

  <div class="cards rise" style="animation-delay:140ms">
    ${cardHtml("Packages", result.totalPackages, "rgba(255,255,255,0.25)")}
    ${cardHtml("Vulnerabilities", result.vulnerabilities.length, result.vulnerabilities.length > 0 ? "#f87171" : "#34d399")}
    ${SEVERITIES.map((s) => cardHtml(s, counts[s], SEVERITY_COLORS[s])).join("")}
  </div>

  ${warningsHtml}
  ${tableHtml}

  <div class="footer">guarded by <b>fixly</b> — detect · remediate · verify</div>

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
