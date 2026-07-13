import * as vscode from "vscode";
import type { ScanResult } from "@fixly/core";
import { renderHtml, buildSummaryText, type ActivityEvent } from "./panel-render";

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
  /** Set once in activate() so the panel tab can show the Fixly mark. */
  static extensionUri: vscode.Uri | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly disposables: vscode.Disposable[] = [];
  private result: ScanResult;
  private onRescan: () => void;
  private activity: ActivityEvent[];

  static show(result: ScanResult, onRescan: () => void, activity: ActivityEvent[] = []): void {
    if (FixlyPanel.current) {
      FixlyPanel.current.onRescan = onRescan;
      FixlyPanel.current.update(result, activity);
      FixlyPanel.current.panel.reveal(vscode.ViewColumn.Beside);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "fixlyReport",
      "Fixly Report",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    if (FixlyPanel.extensionUri) {
      panel.iconPath = vscode.Uri.joinPath(FixlyPanel.extensionUri, "media", "fixly.svg");
    }
    FixlyPanel.current = new FixlyPanel(panel, result, onRescan, activity);
  }

  /** Refresh the report if the panel is already open (e.g. after a guardian
   *  rescan) without stealing focus; no-op when the panel is closed. */
  static updateIfOpen(result: ScanResult, activity: ActivityEvent[] = []): void {
    FixlyPanel.current?.update(result, activity);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    result: ScanResult,
    onRescan: () => void,
    activity: ActivityEvent[]
  ) {
    this.panel = panel;
    this.result = result;
    this.onRescan = onRescan;
    this.activity = activity;

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg: { type: string }) => this.handleMessage(msg),
      null,
      this.disposables
    );
    this.render();
  }

  update(result: ScanResult, activity: ActivityEvent[] = this.activity): void {
    this.result = result;
    this.activity = activity;
    this.render();
  }

  private render(): void {
    this.panel.webview.html = renderHtml(this.result, makeNonce(), this.activity);
  }

  private async handleMessage(msg: { type: string }): Promise<void> {
    switch (msg.type) {
      case "rescan":
        this.onRescan();
        break;
      case "fixAll":
        await vscode.commands.executeCommand("fixly.fixEverything");
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
