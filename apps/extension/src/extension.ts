import * as vscode from "vscode";
import type { ScanResult, Severity } from "@fixly/core";
import { scanWorkspace } from "./scanner";
import { FixlyPanel } from "./panel";
import { updateDiagnostics } from "./diagnostics";
import { FixlyQuickFixProvider } from "./quickfix";

let output: vscode.OutputChannel;
let quickFixes: FixlyQuickFixProvider;
let statusBar: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let lastResult: ScanResult | undefined;
let scanning = false;
let saveDebounce: ReturnType<typeof setTimeout> | undefined;

const MANIFEST_FILES = new Set(["package.json", "package-lock.json"]);
const SAVE_DEBOUNCE_MS = 1_200;

export function activate(context: vscode.ExtensionContext): void {
  output = vscode.window.createOutputChannel("Fixly");
  context.subscriptions.push(output);

  diagnostics = vscode.languages.createDiagnosticCollection("fixly");
  context.subscriptions.push(diagnostics);

  quickFixes = new FixlyQuickFixProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        { language: "json", pattern: "**/package.json" },
        { language: "jsonc", pattern: "**/package.json" },
      ],
      quickFixes,
      FixlyQuickFixProvider.metadata
    )
  );

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.name = "Fixly";
  statusBar.command = "fixly.showReport";
  statusBar.text = "$(shield) Fixly";
  statusBar.tooltip = "Fixly — scan npm dependencies for known vulnerabilities";
  statusBar.show();
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand("fixly.scanCurrentProject", () =>
      runScan({ revealPanel: true, quiet: false })
    ),
    vscode.commands.registerCommand("fixly.showReport", () => {
      if (lastResult) {
        FixlyPanel.show(lastResult, () => runScan({ revealPanel: true, quiet: false }));
      } else {
        runScan({ revealPanel: true, quiet: false });
      }
    }),
    // On-save scanning: saving package.json / package-lock.json re-scans
    // automatically (debounced — npm install touches both files).
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!MANIFEST_FILES.has(doc.fileName.split(/[\\/]/).pop() ?? "")) return;
      const config = vscode.workspace.getConfiguration("fixly");
      if (!config.get<boolean>("scanOnSave", true)) return;
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder || !doc.uri.fsPath.startsWith(folder.uri.fsPath)) return;

      if (saveDebounce) clearTimeout(saveDebounce);
      saveDebounce = setTimeout(() => {
        output.appendLine(
          `[${new Date().toISOString()}] ${doc.fileName.split(/[\\/]/).pop()} saved — rescanning…`
        );
        runScan({ revealPanel: false, quiet: true });
      }, SAVE_DEBOUNCE_MS);
    })
  );
}

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

function updateStatusBar(result: ScanResult): void {
  const counts = severityCounts(result);
  const total = result.vulnerabilities.length;

  if (result.error) {
    statusBar.text = "$(shield) Fixly: scan error";
    statusBar.backgroundColor = undefined;
    statusBar.tooltip = `Fixly — ${result.error.message}`;
    return;
  }

  if (total === 0) {
    statusBar.text = "$(pass) Fixly: clean";
    statusBar.backgroundColor = undefined;
    statusBar.tooltip = `Fixly — no known vulnerabilities across ${result.totalPackages} packages. Click for the full report.`;
    return;
  }

  const parts: string[] = [];
  if (counts.critical) parts.push(`${counts.critical}C`);
  if (counts.high) parts.push(`${counts.high}H`);
  if (counts.medium) parts.push(`${counts.medium}M`);
  if (counts.low) parts.push(`${counts.low}L`);
  if (counts.unknown) parts.push(`${counts.unknown}U`);

  statusBar.text = `$(shield) Fixly: ${parts.join(" ")}`;
  statusBar.backgroundColor =
    counts.critical + counts.high > 0
      ? new vscode.ThemeColor("statusBarItem.errorBackground")
      : counts.medium > 0
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;
  statusBar.tooltip = `Fixly — ${total} known ${total === 1 ? "vulnerability" : "vulnerabilities"} across ${result.totalPackages} packages (${result.transitivePackages} transitive scanned). Click for the full report.`;
}

async function runScan(opts: { revealPanel: boolean; quiet: boolean }): Promise<void> {
  if (scanning) return; // a scan is already in flight — the newest state wins anyway
  scanning = true;

  const log = (msg: string) => output.appendLine(`[${new Date().toISOString()}] ${msg}`);
  if (!opts.quiet) output.show(true);
  log("Starting scan…");
  statusBar.text = "$(sync~spin) Fixly: scanning…";
  statusBar.backgroundColor = undefined;

  await vscode.window.withProgress(
    {
      // Quiet (on-save) scans indicate progress in the status bar only; manual
      // scans keep the notification toast.
      location: opts.quiet
        ? vscode.ProgressLocation.Window
        : vscode.ProgressLocation.Notification,
      title: "Fixly: scanning dependencies…",
    },
    async () => {
      try {
        const outcome = await scanWorkspace(log);
        if (!outcome.ok) {
          log(`Error: ${outcome.error}`);
          statusBar.text = "$(shield) Fixly";
          if (!opts.quiet) vscode.window.showWarningMessage(`Fixly: ${outcome.error}`);
          return;
        }

        const result = outcome.result;
        for (const w of result.warnings) log(`Warning: ${w}`);
        if (result.error) {
          log(`Error: ${result.error.message}`);
          if (!opts.quiet) {
            vscode.window.showWarningMessage(`Fixly: ${result.error.message}`);
          }
        }
        log(
          `Scan complete: ${result.vulnerabilities.length} vulnerabilities across ${result.totalPackages} packages (${result.directPackages} direct, ${result.transitivePackages} transitive).`
        );

        lastResult = result;
        updateStatusBar(result);

        quickFixes.updateFromResult(result);
        const folder = vscode.workspace.workspaceFolders?.[0];
        if (folder) await updateDiagnostics(diagnostics, folder, result);

        if (opts.revealPanel) {
          FixlyPanel.show(result, () => runScan({ revealPanel: true, quiet: false }));
        } else {
          FixlyPanel.updateIfOpen(result);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`Unexpected error: ${msg}`);
        statusBar.text = "$(shield) Fixly";
        if (!opts.quiet) vscode.window.showErrorMessage(`Fixly: scan failed — ${msg}`);
      } finally {
        scanning = false;
      }
    }
  );
}

export function deactivate(): void {
  if (saveDebounce) clearTimeout(saveDebounce);
}
