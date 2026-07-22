import * as vscode from "vscode";

// Serves proposed file contents as read-only virtual documents under the
// `fixly-preview:` scheme so the remediation plan can be shown in a
// side-by-side diff (via the built-in `vscode.diff` command) before anything
// is written to disk. The path ends in `.json` so the diff gets JSON syntax
// highlighting; content is overwritten (and a change fired) on each preview.

export const PREVIEW_SCHEME = "fixly-preview";

export class ProposedContentProvider
  implements vscode.TextDocumentContentProvider
{
  private readonly contents = new Map<string, string>();
  private readonly onDidChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
  readonly onDidChange = this.onDidChangeEmitter.event;

  /** Publish the proposed content and return the virtual URI to diff against. */
  set(content: string): vscode.Uri {
    const uri = vscode.Uri.from({ scheme: PREVIEW_SCHEME, path: "/package.json" });
    this.contents.set(uri.toString(), content);
    this.onDidChangeEmitter.fire(uri);
    return uri;
  }

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.contents.get(uri.toString()) ?? "";
  }

  dispose(): void {
    this.onDidChangeEmitter.dispose();
  }
}
