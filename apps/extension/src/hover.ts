import * as vscode from "vscode";
import type { PackageAdvice } from "./advice";

// Hover cards on package.json: hovering a vulnerable dependency's name shows
// the full remediation card (advisories + the resolution engine's decision in
// plain language). Content comes from advice.ts; this module only matches the
// hovered position to a dependency key. The document is re-parsed at hover
// time, so cards stay anchored correctly even after unsaved edits.

export class FixlyHoverProvider implements vscode.HoverProvider {
  private advice = new Map<string, PackageAdvice>();

  /** Refresh from a completed scan's advice (same map diagnostics use). */
  update(advice: Map<string, PackageAdvice>): void {
    this.advice = advice;
  }

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.Hover | null {
    // A quoted JSON key followed by a colon — i.e. a dependency name, never a
    // version value or a manifest field value that happens to match a name.
    const keyRange = document.getWordRangeAtPosition(
      position,
      /"[^"\s]+"(?=\s*:)/
    );
    if (!keyRange) return null;

    const pkg = document.getText(keyRange).slice(1, -1);
    const entry = this.advice.get(pkg);
    if (!entry) return null;

    // Untrusted markdown (advisory titles are third-party data): command links
    // and raw HTML stay disabled — MarkdownString is untrusted by default.
    const card = new vscode.MarkdownString(entry.hoverMarkdown);
    return new vscode.Hover(card, keyRange);
  }
}
