import * as vscode from "vscode";
import { buildRemediationPlan, type ScanResult } from "@fixly/core";

// Quick Fixes on Fixly diagnostics: the lightbulb on a vulnerable direct
// dependency rewrites its version range in package.json to the remediation
// engine's target (highest fixed version across that package's findings),
// preserving the author's `^`/`~` style. Saving then triggers the on-save
// rescan, so the diagnostic disappears once the fix is real — a full
// fix→verify loop without leaving the editor.

interface PackageFix {
  targetVersion: string;
  resolves: number;
}

/** Keep the caller's range style, mirroring core's applyRemediationPlan. */
function rewriteRange(oldRange: string, target: string): string {
  if (oldRange.startsWith("^")) return `^${target}`;
  if (oldRange.startsWith("~")) return `~${target}`;
  if (/^\d/.test(oldRange)) return target;
  return `^${target}`;
}

export class FixlyQuickFixProvider implements vscode.CodeActionProvider {
  static readonly metadata: vscode.CodeActionProviderMetadata = {
    providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
  };

  private fixes = new Map<string, PackageFix>();

  /** Refresh available fixes from a completed scan (direct upgrades only —
   *  transitive overrides and malware removals stay in the report panel). */
  updateFromResult(result: ScanResult): void {
    this.fixes.clear();
    const plan = buildRemediationPlan(result);
    for (const action of plan.actions) {
      if (action.kind === "upgrade" && action.targetVersion) {
        this.fixes.set(action.package, {
          targetVersion: action.targetVersion,
          resolves: action.resolves.length,
        });
      }
    }
  }

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "Fixly") continue;
      // The diagnostic range IS the package name in `"name": "range"`.
      const pkg = document.getText(diagnostic.range);
      const fix = this.fixes.get(pkg);
      if (!fix) continue;

      const valueRange = this.findValueRange(document, diagnostic.range);
      if (!valueRange) continue;
      const oldRange = document.getText(valueRange);
      const newRange = rewriteRange(oldRange, fix.targetVersion);
      if (newRange === oldRange) continue;

      const action = new vscode.CodeAction(
        `Fixly: upgrade ${pkg} to ${fix.targetVersion} (fixes ${fix.resolves} ${fix.resolves === 1 ? "advisory" : "advisories"})`,
        vscode.CodeActionKind.QuickFix
      );
      action.diagnostics = [diagnostic];
      action.isPreferred = true;
      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, valueRange, newRange);
      actions.push(action);
    }
    return actions;
  }

  /** Range of the version string (without quotes) after `"pkg":`. */
  private findValueRange(
    document: vscode.TextDocument,
    nameRange: vscode.Range
  ): vscode.Range | null {
    const text = document.getText();
    const afterName = document.offsetAt(nameRange.end) + 1; // past the closing quote
    const match = /^\s*:\s*"([^"]*)"/.exec(text.slice(afterName, afterName + 80));
    if (!match) return null;
    const valueStart = afterName + match[0].length - match[1].length - 1;
    return new vscode.Range(
      document.positionAt(valueStart),
      document.positionAt(valueStart + match[1].length)
    );
  }
}
