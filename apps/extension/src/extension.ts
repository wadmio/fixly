import * as vscode from "vscode";
import {
  computeGrade,
  diffFindingSnapshot,
  snapshotFindings,
  type FindingSnapshot,
  type ScanResult,
  type ScanVulnerability,
} from "@fixly/core";
import { scanWorkspace } from "./scanner";
import { FixlyPanel } from "./panel";
import { updateDiagnostics } from "./diagnostics";
import { FixlyQuickFixProvider } from "./quickfix";
import { remediateInEditor } from "./remediator";
import type { ActivityEvent } from "./panel-render";

let output: vscode.OutputChannel;
let quickFixes: FixlyQuickFixProvider;
let statusBar: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let lastResult: ScanResult | undefined;
let scanning = false;
let pendingRescan = false;
let remediating = false;
let changeDebounce: ReturnType<typeof setTimeout> | undefined;
let advisoryTimer: ReturnType<typeof setInterval> | undefined;

// The guardian's memory: findings seen on the last scan. null until the
// baseline scan — existing findings are NEVER auto-fixed on startup.
let snapshot: FindingSnapshot | null = null;
// When the pending scan was triggered (file change on disk) — the start of
// the MTTR clock.
let detectedAt = 0;

const activity: ActivityEvent[] = [];
const ACTIVITY_CAP = 50;

const CHANGE_DEBOUNCE_MS = 1_200;

function logLine(msg: string): void {
  output.appendLine(`[${new Date().toTimeString().slice(0, 8)}] ${msg}`);
}

function clock(): string {
  return new Date().toTimeString().slice(0, 8);
}

function record(kind: ActivityEvent["kind"], text: string, mttrMs?: number): void {
  activity.unshift({ at: clock(), kind, text, mttrMs });
  if (activity.length > ACTIVITY_CAP) activity.pop();
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("fixly");
}

export function activate(context: vscode.ExtensionContext): void {
  FixlyPanel.extensionUri = context.extensionUri;
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
  statusBar.tooltip = "Fixly — real-time dependency remediation";
  statusBar.show();
  context.subscriptions.push(statusBar);

  context.subscriptions.push(
    vscode.commands.registerCommand("fixly.scanCurrentProject", () =>
      runScan({ revealPanel: true, quiet: false })
    ),
    vscode.commands.registerCommand("fixly.showReport", () => {
      if (lastResult) {
        FixlyPanel.show(lastResult, () => runScan({ revealPanel: true, quiet: false }), activity);
      } else {
        runScan({ revealPanel: true, quiet: false });
      }
    }),
    vscode.commands.registerCommand("fixly.fixEverything", () => fixEverything())
  );

  // Watch the manifest files ON DISK — editor saves, terminal `npm install`,
  // and AI-agent writes all land here (onDidSaveTextDocument only sees the
  // first of those). This is the guardian's detection trigger.
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (folder) {
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(folder, "{package.json,package-lock.json}")
    );
    const onChange = (uri: vscode.Uri) => {
      if (remediating) return; // our own writes
      if (!config().get<boolean>("scanOnSave", true)) return;
      if (changeDebounce) clearTimeout(changeDebounce);
      const at = Date.now();
      changeDebounce = setTimeout(() => {
        changeDebounce = undefined;
        detectedAt = at;
        logLine(`${uri.fsPath.split(/[\\/]/).pop()} changed on disk — rescanning…`);
        runScan({ revealPanel: false, quiet: true });
      }, CHANGE_DEBOUNCE_MS);
    };
    watcher.onDidChange(onChange);
    watcher.onDidCreate(onChange);
    context.subscriptions.push(watcher);

    // Baseline scan on activation so the status bar shows the grade the
    // moment the project opens. Baselines never auto-fix.
    void runScan({ revealPanel: false, quiet: true });

    // The advisory clock: re-scan on an interval so a CVE published while
    // you code surfaces (and is remediated) with zero local changes.
    const intervalMin = config().get<number>("advisoryIntervalMinutes", 10);
    if (intervalMin > 0) {
      advisoryTimer = setInterval(
        () => {
          if (!scanning && !remediating) {
            detectedAt = Date.now();
            logLine("Advisory clock: periodic re-scan…");
            void runScan({ revealPanel: false, quiet: true });
          }
        },
        Math.max(1, intervalMin) * 60_000
      );
    }
  }
}

function updateStatusBar(result: ScanResult): void {
  if (result.error) {
    statusBar.text = "$(shield) Fixly: scan error";
    statusBar.backgroundColor = undefined;
    statusBar.tooltip = `Fixly — ${result.error.message}`;
    return;
  }
  const grade = computeGrade(result);
  const total = result.vulnerabilities.length;
  statusBar.text = `$(shield) Fixly ${grade.grade} · ${grade.score}`;
  statusBar.backgroundColor =
    grade.grade === "F" || grade.grade === "D"
      ? new vscode.ThemeColor("statusBarItem.errorBackground")
      : grade.grade === "C"
        ? new vscode.ThemeColor("statusBarItem.warningBackground")
        : undefined;
  statusBar.tooltip =
    total === 0
      ? `Fixly Score ${grade.grade} (${grade.score}/100) — no known vulnerabilities across ${result.totalPackages} packages. Click for the report.`
      : `Fixly Score ${grade.grade} (${grade.score}/100) — ${total} known ${total === 1 ? "vulnerability" : "vulnerabilities"} across ${result.totalPackages} packages. Click for the report.`;
}

function applyResultToUi(result: ScanResult): void {
  lastResult = result;
  updateStatusBar(result);
  quickFixes.updateFromResult(result);
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (folder) void updateDiagnostics(diagnostics, folder, result);
  FixlyPanel.updateIfOpen(result, activity);
}

async function runScan(opts: { revealPanel: boolean; quiet: boolean }): Promise<void> {
  if (scanning) {
    pendingRescan = true;
    return;
  }
  scanning = true;

  if (!opts.quiet) output.show(true);
  logLine("Starting scan…");
  statusBar.text = "$(sync~spin) Fixly: scanning…";
  statusBar.backgroundColor = undefined;

  await vscode.window.withProgress(
    {
      location: opts.quiet
        ? vscode.ProgressLocation.Window
        : vscode.ProgressLocation.Notification,
      title: "Fixly: scanning dependencies…",
    },
    async () => {
      try {
        const outcome = await scanWorkspace(logLine);
        if (!outcome.ok) {
          logLine(`Error: ${outcome.error}`);
          statusBar.text = "$(shield) Fixly";
          if (!opts.quiet) vscode.window.showWarningMessage(`Fixly: ${outcome.error}`);
          return;
        }

        const result = outcome.result;
        for (const w of result.warnings) logLine(`Warning: ${w}`);
        if (result.error) {
          logLine(`Error: ${result.error.message}`);
          if (!opts.quiet) {
            vscode.window.showWarningMessage(`Fixly: ${result.error.message}`);
          }
          applyResultToUi(result);
          return;
        }
        logLine(
          `Scan complete: ${result.vulnerabilities.length} vulnerabilities across ${result.totalPackages} packages (${result.directPackages} direct, ${result.transitivePackages} transitive).`
        );

        await handleScanResult(result, opts);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logLine(`Unexpected error: ${msg}`);
        statusBar.text = "$(shield) Fixly";
        if (!opts.quiet) vscode.window.showErrorMessage(`Fixly: scan failed — ${msg}`);
      } finally {
        scanning = false;
        if (pendingRescan) {
          pendingRescan = false;
          void runScan({ revealPanel: false, quiet: true });
        }
      }
    }
  );
}

/** The guardian: baseline → diff → auto-remediate. */
async function handleScanResult(
  result: ScanResult,
  opts: { revealPanel: boolean; quiet: boolean }
): Promise<void> {
  const grade = computeGrade(result);

  if (snapshot === null) {
    // First scan of the session — report, never auto-fix.
    snapshot = snapshotFindings(result.vulnerabilities);
    const n = result.vulnerabilities.length;
    record(
      "baseline",
      `baseline ${grade.grade} (${grade.score}/100) — ${n} existing finding${n === 1 ? "" : "s"}, ${result.totalPackages} packages`
    );
    applyResultToUi(result);
    if (opts.revealPanel) {
      FixlyPanel.show(result, () => runScan({ revealPanel: true, quiet: false }), activity);
    }
    if (n > 0) {
      vscode.window
        .showWarningMessage(
          `Fixly — baseline ${grade.grade} (${grade.score}/100), ${n} existing finding${n === 1 ? "" : "s"}. Not auto-fixed.`,
          "Fix All & Verify",
          "Open Report"
        )
        .then((choice) => {
          if (choice === "Fix All & Verify") void fixEverything();
          else if (choice === "Open Report") void vscode.commands.executeCommand("fixly.showReport");
        });
    }
    return;
  }

  const diff = diffFindingSnapshot(snapshot, result.vulnerabilities);
  const triggered = [...diff.added, ...diff.escalated];

  if (diff.resolvedKeys.length > 0 && triggered.length === 0) {
    record(
      "resolved",
      `${diff.resolvedKeys.length} finding${diff.resolvedKeys.length === 1 ? "" : "s"} resolved — grade ${grade.grade} (${grade.score}/100)`
    );
  }

  if (triggered.length === 0) {
    snapshot = snapshotFindings(result.vulnerabilities);
    applyResultToUi(result);
    if (opts.revealPanel) {
      FixlyPanel.show(result, () => runScan({ revealPanel: true, quiet: false }), activity);
    }
    return;
  }

  // ---- new (or newly exploited) findings — the event ----
  const packages = [...new Set(triggered.map((v) => v.package))].join(", ");
  const kind = diff.added.length > 0 ? "detected" : "escalation";
  const summary =
    kind === "escalation"
      ? `${packages} now known-exploited (CISA KEV)`
      : `${triggered.length} new vulnerabilit${triggered.length === 1 ? "y" : "ies"} in ${packages} — grade ${grade.grade} (${grade.score}/100)`;
  record(kind, summary);
  logLine(summary);
  applyResultToUi(result);

  const startedAt = detectedAt || Date.now();
  if (config().get<boolean>("autoRemediate", true)) {
    vscode.window.showWarningMessage(`Fixly — ${summary}. Remediating…`);
    await runRemediation(result, triggered, startedAt);
  } else {
    snapshot = snapshotFindings(result.vulnerabilities);
    vscode.window
      .showWarningMessage(`Fixly — ${summary}.`, "Fix & Verify", "Open Report")
      .then((choice) => {
        if (choice === "Fix & Verify") void runRemediation(result, triggered, Date.now());
        else if (choice === "Open Report") void vscode.commands.executeCommand("fixly.showReport");
      });
  }
}

/** Fix every fixable finding in the last scan (baseline toast / panel button). */
async function fixEverything(): Promise<void> {
  if (!lastResult || lastResult.error) {
    vscode.window.showWarningMessage("Fixly: run a scan first.");
    return;
  }
  if (lastResult.vulnerabilities.length === 0) {
    vscode.window.showInformationMessage("Fixly: nothing to fix — the project is clean.");
    return;
  }
  await runRemediation(lastResult, lastResult.vulnerabilities, Date.now());
}

async function runRemediation(
  result: ScanResult,
  triggeredBy: ScanVulnerability[],
  startedAt: number
): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder || remediating) return;
  remediating = true;
  statusBar.text = "$(sync~spin) Fixly: remediating…";
  statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");

  try {
    const outcome = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Fixly: remediating — fix → install → verify…",
      },
      () => remediateInEditor(folder, result, triggeredBy, startedAt, logLine)
    );

    if (outcome.verified && outcome.verifyResult && outcome.after) {
      const mttr = ((outcome.mttrMs ?? 0) / 1000).toFixed(1);
      const unfixableNote =
        outcome.plan.unfixable.length > 0
          ? ` (${outcome.plan.unfixable.length} finding${outcome.plan.unfixable.length === 1 ? "" : "s"} have no published fix yet)`
          : "";
      record(
        "remediated",
        `${outcome.changes.length} package${outcome.changes.length === 1 ? "" : "s"} fixed — grade ${outcome.after.grade} (${outcome.after.score}/100), verified${unfixableNote}`,
        outcome.mttrMs ?? undefined
      );
      logLine(`Remediated in ${mttr}s — verified.`);
      snapshot = snapshotFindings(outcome.verifyResult.vulnerabilities);
      applyResultToUi(outcome.verifyResult);
      vscode.window
        .showInformationMessage(
          `Fixly — remediated in ${mttr}s. Grade ${outcome.after.grade} (${outcome.after.score}/100), verified.`,
          "Open Report"
        )
        .then((choice) => {
          if (choice === "Open Report") void vscode.commands.executeCommand("fixly.showReport");
        });
    } else {
      record("failed", `remediation failed: ${outcome.failure ?? "unknown"}`);
      logLine(`Remediation failed: ${outcome.failure ?? "unknown"}`);
      // Keep the detection scan as the snapshot so the same findings don't
      // re-trigger a remediation loop every cycle.
      snapshot = snapshotFindings(
        (outcome.verifyResult ?? result).vulnerabilities
      );
      if (outcome.verifyResult) applyResultToUi(outcome.verifyResult);
      vscode.window
        .showErrorMessage(
          `Fixly — remediation failed: ${outcome.failure ?? "unknown"}.`,
          "Open Report"
        )
        .then((choice) => {
          if (choice === "Open Report") void vscode.commands.executeCommand("fixly.showReport");
        });
    }
  } finally {
    remediating = false;
    if (lastResult) updateStatusBar(lastResult);
  }
}

export function deactivate(): void {
  if (changeDebounce) clearTimeout(changeDebounce);
  if (advisoryTimer) clearInterval(advisoryTimer);
}
