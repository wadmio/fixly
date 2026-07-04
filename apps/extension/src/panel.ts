import * as vscode from "vscode";
import type { ScanResult, ScanVulnerability, Severity } from "@fixly/core";

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

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildSummaryText(result: ScanResult): string {
  const counts = severityCounts(result);
  const lines = [
    `Fixly scan — ${result.repo}`,
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

function renderHtml(result: ScanResult, nonce: string): string {
  const counts = severityCounts(result);

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
  </script>
</body>
</html>`;
}

function makeNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let text = "";
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}

/** Singleton webview panel that renders a scan report and relays actions. */
export class FixlyPanel {
  private static current: FixlyPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];
  private result: ScanResult;
  private onRescan: () => void;

  static show(result: ScanResult, onRescan: () => void): void {
    if (FixlyPanel.current) {
      FixlyPanel.current.onRescan = onRescan;
      FixlyPanel.current.update(result);
      FixlyPanel.current.panel.reveal(vscode.ViewColumn.Beside);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "fixlyReport",
      "Fixly Report",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    FixlyPanel.current = new FixlyPanel(panel, result, onRescan);
  }

  /** Refresh the report if the panel is already open (e.g. after an on-save
   *  rescan) without stealing focus; no-op when the panel is closed. */
  static updateIfOpen(result: ScanResult): void {
    FixlyPanel.current?.update(result);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    result: ScanResult,
    onRescan: () => void
  ) {
    this.panel = panel;
    this.result = result;
    this.onRescan = onRescan;

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg: { type: string }) => this.handleMessage(msg),
      null,
      this.disposables
    );
    this.render();
  }

  update(result: ScanResult): void {
    this.result = result;
    this.render();
  }

  private render(): void {
    this.panel.webview.html = renderHtml(this.result, makeNonce());
  }

  private async handleMessage(msg: { type: string }): Promise<void> {
    switch (msg.type) {
      case "rescan":
        this.onRescan();
        break;
      case "copySummary":
        await vscode.env.clipboard.writeText(buildSummaryText(this.result));
        vscode.window.showInformationMessage("Fixly: summary copied to clipboard.");
        break;
      case "exportJson": {
        const uri = await vscode.window.showSaveDialog({
          saveLabel: "Export Fixly report",
          filters: { JSON: ["json"] },
          defaultUri: vscode.Uri.file("fixly-report.json"),
        });
        if (uri) {
          await vscode.workspace.fs.writeFile(
            uri,
            Buffer.from(JSON.stringify(this.result, null, 2), "utf-8")
          );
          vscode.window.showInformationMessage(`Fixly: report saved to ${uri.fsPath}`);
        }
        break;
      }
    }
  }

  private dispose(): void {
    FixlyPanel.current = undefined;
    this.panel.dispose();
    let d: vscode.Disposable | undefined;
    while ((d = this.disposables.pop())) d.dispose();
  }
}
