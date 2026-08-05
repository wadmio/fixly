import * as vscode from "vscode";
import type { DiagnosticTier, PackageAdvice } from "./advice";

// Inline editor alerts: one diagnostic per vulnerable DIRECT dependency,
// anchored to its exact `"name": "range"` key in package.json. Message, tier
// (risk + CVSS, not CVSS alone), and hover content all come from advice.ts —
// this module only locates ranges and creates vscode objects. Transitive
// findings have no line to point at — they live in the panel and status bar.

const TIER_TO_SEVERITY: Record<DiagnosticTier, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

/**
 * Locate the `"pkg":` dependency key in package.json text. Only occurrences
 * followed by `: "<value>"` count, so a package that shares its name with a
 * manifest field value (e.g. `"name": "lodash"`) is never matched.
 */
export function findDependencyRange(
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

/**
 * Refresh the Fixly diagnostics on the workspace package.json from the
 * per-package advice of a completed scan. Clears previous findings first so
 * resolved issues disappear.
 */
export async function updateDiagnostics(
  collection: vscode.DiagnosticCollection,
  folder: vscode.WorkspaceFolder,
  advice: Map<string, PackageAdvice>
): Promise<void> {
  const uri = vscode.Uri.joinPath(folder.uri, "package.json");
  collection.clear();

  if (advice.size === 0) {
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

  const diagnostics: vscode.Diagnostic[] = [];
  for (const [pkg, entry] of advice) {
    const range =
      findDependencyRange(doc, text, pkg) ?? new vscode.Range(0, 0, 0, 1);

    const diagnostic = new vscode.Diagnostic(
      range,
      entry.message,
      TIER_TO_SEVERITY[entry.tier]
    );
    diagnostic.source = "Fixly";
    diagnostic.code = entry.worstReference
      ? { value: entry.worstOsvId, target: vscode.Uri.parse(entry.worstReference) }
      : entry.worstOsvId;
    diagnostics.push(diagnostic);
  }

  collection.set(uri, diagnostics);
}
