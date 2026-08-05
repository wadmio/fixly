import * as vscode from "vscode";
import type { DependencyGraph, ScanResult } from "@fixly/core";
import { renderHtml, buildSummaryText } from "./panel-render";

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
  private graph: DependencyGraph | null;
  private onRescan: () => void;

  static show(
    result: ScanResult,
    graph: DependencyGraph | null,
    onRescan: () => void
  ): void {
    if (FixlyPanel.current) {
      FixlyPanel.current.onRescan = onRescan;
      FixlyPanel.current.update(result, graph);
      FixlyPanel.current.panel.reveal(vscode.ViewColumn.Beside);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "fixlyReport",
      "Fixly Report",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    FixlyPanel.current = new FixlyPanel(panel, result, graph, onRescan);
  }

  /** Refresh the report if the panel is already open (e.g. after an on-save
   *  rescan) without stealing focus; no-op when the panel is closed. */
  static updateIfOpen(result: ScanResult, graph: DependencyGraph | null): void {
    FixlyPanel.current?.update(result, graph);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    result: ScanResult,
    graph: DependencyGraph | null,
    onRescan: () => void
  ) {
    this.panel = panel;
    this.result = result;
    this.graph = graph;
    this.onRescan = onRescan;

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg: { type: string }) => this.handleMessage(msg),
      null,
      this.disposables
    );
    this.render();
  }

  update(result: ScanResult, graph: DependencyGraph | null): void {
    this.result = result;
    this.graph = graph;
    this.render();
  }

  private render(): void {
    this.panel.webview.html = renderHtml(this.result, makeNonce(), this.graph);
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
