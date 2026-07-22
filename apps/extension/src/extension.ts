import * as vscode from "vscode";
import { buildRemediationPlan, type ScanResult, type Severity } from "@fixly/core";
import { scanWorkspace } from "./scanner";
import { FixlyPanel } from "./panel";
import { updateDiagnostics } from "./diagnostics";
import { FixlyQuickFixProvider } from "./quickfix";
import { applyRemediationPlanToWorkspace } from "./apply-plan";
import { ProposedContentProvider, PREVIEW_SCHEME } from "./preview";
import { debounce, type Debounced } from "./debounce";

interface RunScanOpts {
  revealPanel: boolean;
  quiet: boolean;
  /** Unsaved package.json text for as-you-type scans (see scanner.ts). */
  packageJsonText?: string;
}

let output: vscode.OutputChannel;
let quickFixes: FixlyQuickFixProvider;
let preview: ProposedContentProvider;
let statusBar: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let lastResult: ScanResult | undefined;
let scanning = false;
// The freshest request that arrived while a scan was in flight; run when it
// finishes so the latest text always wins and stale results are dropped.
let pendingScan: RunScanOpts | null = null;
let saveDebounce: ReturnType<typeof setTimeout> | undefined;
let typeDebounce: Debounced<[string]> | undefined;

const MANIFEST_FILES = new Set(["package.json", "package-lock.json"]);
const SAVE_DEBOUNCE_MS = 1_200;
const TYPE_DEBOUNCE_MS = 1_500;

function basename(fsPath: string): string {
  return fsPath.split(/[\\/]/).pop() ?? "";
}

export function activate(context: vscode.ExtensionContext): void {
  output = vscode.window.createOutputChannel("Fixly");
  context.subscriptions.push(output);

  diagnostics = vscode.languages.createDiagnosticCollection("fixly");
  context.subscriptions.push(diagnostics);

  preview = new ProposedContentProvider();
  context.subscriptions.push(
    preview,
    vscode.workspace.registerTextDocumentContentProvider(PREVIEW_SCHEME, preview)
  );

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
    vscode.commands.registerCommand("fixly.applyRemediationPlan", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showWarningMessage(
          "Fixly: open a Node.js project folder first."
        );
        return;
      }
      // Need a scan to plan from; run one if the user hasn't scanned yet.
      if (!lastResult) await runScan({ revealPanel: false, quiet: false });
      if (!lastResult) return; // scan failed — runScan already surfaced why
      const log = (msg: string) =>
        output.appendLine(`[${new Date().toISOString()}] ${msg}`);
      await applyRemediationPlanToWorkspace(folder, lastResult, preview, log);
    }),
    // On-save scanning: saving package.json / package-lock.json re-scans
    // automatically (debounced — npm install touches both files).
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (!MANIFEST_FILES.has(basename(doc.fileName))) return;
      const config = vscode.workspace.getConfiguration("fixly");
      if (!config.get<boolean>("scanOnSave", true)) return;
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder || !doc.uri.fsPath.startsWith(folder.uri.fsPath)) return;

      if (saveDebounce) clearTimeout(saveDebounce);
      saveDebounce = setTimeout(() => {
        output.appendLine(
          `[${new Date().toISOString()}] ${basename(doc.fileName)} saved — rescanning…`
        );
        runScan({ revealPanel: false, quiet: true });
      }, SAVE_DEBOUNCE_MS);
    }),
    // As-you-type scanning (opt-in, fixly.scanOnType): re-scan on edits to
    // package.json using the unsaved buffer text — no save required. Debounced,
    // and the coalescing in runScan drops stale results from rapid typing.
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (basename(doc.fileName) !== "package.json") return;
      const config = vscode.workspace.getConfiguration("fixly");
      if (!config.get<boolean>("scanOnType", false)) return;
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder || !doc.uri.fsPath.startsWith(folder.uri.fsPath)) return;

      typeDebounce ??= debounce((text: string) => {
        output.appendLine(
          `[${new Date().toISOString()}] package.json edited — rescanning (unsaved buffer)…`
        );
        runScan({ revealPanel: false, quiet: true, packageJsonText: text });
      }, TYPE_DEBOUNCE_MS);
      typeDebounce(doc.getText());
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
  const plan = buildRemediationPlan(result);
  const forecastNote =
    plan.actions.length > 0
      ? ` Fix plan → ${plan.forecast.after.grade} (${plan.forecast.after.score}).`
      : "";
  statusBar.tooltip = `Fixly — ${total} known ${total === 1 ? "vulnerability" : "vulnerabilities"} across ${result.totalPackages} packages (${result.transitivePackages} transitive scanned). Click for the full report.${forecastNote}`;
}

async function runScan(opts: RunScanOpts): Promise<void> {
  if (scanning) {
    // Coalesce: a scan is running — remember the freshest request and run it
    // when the current one finishes, so the latest text wins and no trigger is
    // silently dropped.
    pendingScan = opts;
    return;
  }
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
        const outcome = await scanWorkspace(log, {
          packageJsonText: opts.packageJsonText,
        });
        // A newer edit arrived mid-scan — this result is already stale; skip
        // applying it and let the queued rescan produce the current state.
        if (pendingScan) {
          log("Newer change pending — discarding stale scan result.");
          return;
        }
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

  // Run the freshest request that arrived while this scan was in flight.
  if (pendingScan) {
    const next = pendingScan;
    pendingScan = null;
    void runScan(next);
  }
}

export function deactivate(): void {
  if (saveDebounce) clearTimeout(saveDebounce);
  typeDebounce?.cancel();
}
