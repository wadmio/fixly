import * as vscode from "vscode";
import type { ScanResult, ScanVulnerability, Severity } from "@fixly/core";

// Inline editor alerts: one diagnostic per vulnerable DIRECT dependency,
// anchored to its exact `"name": "range"` key in package.json. Transitive
// findings have no line to point at — they live in the panel and status bar.

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

function toDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Locate the `"pkg":` dependency key in package.json text. Only occurrences
 * followed by `: "<value>"` count, so a package that shares its name with a
 * manifest field value (e.g. `"name": "lodash"`) is never matched.
 */
function findDependencyRange(
  doc: vscode.TextDocument,
  text: string,
  pkg: string
): vscode.Range | null {
  const needle = `"${pkg}"`;
  let from = 0;
  for (;;) {
    const idx = text.indexOf(needle, from);
    if (idx === -1) return null;
    const after = text.slice(idx + needle.length, idx + needle.length + 40);
    if (/^\s*:\s*"/.test(after)) {
      return new vscode.Range(
        doc.positionAt(idx + 1),
        doc.positionAt(idx + 1 + pkg.length)
      );
    }
    from = idx + needle.length;
  }
}

function buildMessage(pkg: string, vulns: ScanVulnerability[]): string {
  const worst = vulns[0];
  const count = vulns.length;
  const idLabel = worst.cveId ?? worst.osvId;
  const parts = [
    `${pkg}@${worst.installedVersion}: ${count} known ${count === 1 ? "vulnerability" : "vulnerabilities"} — worst is ${worst.severity} (${idLabel}).`,
  ];
  if (worst.fixedVersion) {
    parts.push(`Upgrade to ${worst.fixedVersion} or later.`);
  }
  return parts.join(" ");
}

/**
 * Refresh the Fixly diagnostics on the workspace package.json from a completed
 * scan. Clears previous findings first so resolved issues disappear.
 */
export async function updateDiagnostics(
  collection: vscode.DiagnosticCollection,
  folder: vscode.WorkspaceFolder,
  result: ScanResult
): Promise<void> {
  const uri = vscode.Uri.joinPath(folder.uri, "package.json");
  collection.clear();

  const direct = result.vulnerabilities.filter((v) => v.dependencyType !== "transitive");
  if (direct.length === 0) {
    collection.set(uri, []);
    return;
  }

  let doc: vscode.TextDocument;
  try {
    doc = await vscode.workspace.openTextDocument(uri);
  } catch {
    return; // package.json disappeared between scan and render
  }
  const text = doc.getText();

  const byPackage = new Map<string, ScanVulnerability[]>();
  for (const v of direct) {
    const list = byPackage.get(v.package);
    if (list) list.push(v);
    else byPackage.set(v.package, [v]);
  }

  const diagnostics: vscode.Diagnostic[] = [];
  for (const [pkg, vulns] of byPackage) {
    vulns.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    const worst = vulns[0];
    const range =
      findDependencyRange(doc, text, pkg) ?? new vscode.Range(0, 0, 0, 1);

    const diagnostic = new vscode.Diagnostic(
      range,
      buildMessage(pkg, vulns),
      toDiagnosticSeverity(worst.severity)
    );
    diagnostic.source = "Fixly";
    diagnostic.code = worst.references[0]
      ? { value: worst.osvId, target: vscode.Uri.parse(worst.references[0]) }
      : worst.osvId;
    diagnostics.push(diagnostic);
  }

  collection.set(uri, diagnostics);
}
