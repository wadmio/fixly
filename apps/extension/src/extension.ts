import * as vscode from "vscode";
import { scanWorkspace } from "./scanner";
import { FixlyPanel } from "./panel";

let output: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  output = vscode.window.createOutputChannel("Fixly");
  context.subscriptions.push(output);

  context.subscriptions.push(
    vscode.commands.registerCommand("fixly.scanCurrentProject", () => runScan())
  );
}

async function runScan(): Promise<void> {
  const log = (msg: string) => output.appendLine(`[${new Date().toISOString()}] ${msg}`);
  output.show(true);
  log("Starting scan…");

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Fixly: scanning dependencies…",
    },
    async () => {
      try {
        const outcome = await scanWorkspace(log);
        if (!outcome.ok) {
          log(`Error: ${outcome.error}`);
          vscode.window.showWarningMessage(`Fixly: ${outcome.error}`);
          return;
        }

        for (const w of outcome.result.warnings) log(`Warning: ${w}`);
        if (outcome.result.error) {
          log(`Error: ${outcome.result.error}`);
          vscode.window.showWarningMessage(`Fixly: ${outcome.result.error}`);
        }

        FixlyPanel.show(outcome.result, () => runScan());
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`Unexpected error: ${msg}`);
        vscode.window.showErrorMessage(`Fixly: scan failed — ${msg}`);
      }
    }
  );
}

export function deactivate(): void {
  // no-op
}
