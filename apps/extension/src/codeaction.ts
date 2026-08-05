import * as vscode from "vscode";

// Lightbulb on each Fixly diagnostic in package.json. The previous quick-fix
// provider (removed with the v0.2.0 apply flow) rewrote version ranges; this
// one only copies advice — a per-package fix brief — to the clipboard. Fixly
// analyzes and verifies, never modifies.

export class FixlyCodeActionProvider implements vscode.CodeActionProvider {
  static readonly metadata: vscode.CodeActionProviderMetadata = {
    providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
  };

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "Fixly") continue;
      // Diagnostics are anchored exactly on the dependency name.
      const pkg = document.getText(diagnostic.range);
      if (!pkg) continue;
      const action = new vscode.CodeAction(
        `Fixly: Copy Fix Brief for ${pkg}`,
        vscode.CodeActionKind.QuickFix
      );
      action.command = {
        command: "fixly.copyPackageBrief",
        title: `Copy Fix Brief for ${pkg}`,
        arguments: [pkg],
      };
      action.diagnostics = [diagnostic];
      actions.push(action);
    }
    return actions;
  }
}
