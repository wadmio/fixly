import * as vscode from "vscode";
import {
  applyRemediationPlan,
  buildRemediationPlan,
  type RemediationAction,
  type ScanResult,
} from "@fixly/core";
import type { ProposedContentProvider } from "./preview";

// "Fixly: Apply Remediation Plan" — takes the last scan's remediation plan and
// writes the file-editable parts into package.json in one edit: bumps every
// direct "upgrade" range (preserving the author's ^/~ style) and adds/updates
// the "overrides" block for every transitive "override". The file rewrite is
// delegated to core's applyRemediationPlan so this matches `fixly fix --write`
// exactly. Before anything is written the proposed package.json is shown in a
// side-by-side diff and gated behind a modal confirmation. Malware "remove"
// actions are NEVER applied to files — they surface as a warning listing the
// npm uninstall commands to run by hand. No installs are run and node_modules
// is never touched; the user realizes the fixes with `npm install`, which (on
// save) triggers the on-save rescan.

/**
 * Apply the remediation plan for a completed scan to the workspace
 * package.json. Shows a diff preview + modal confirmation before writing; only
 * upgrade/override actions edit files; malware removals are reported for the
 * user to run manually.
 */
export async function applyRemediationPlanToWorkspace(
  folder: vscode.WorkspaceFolder,
  result: ScanResult,
  preview: ProposedContentProvider,
  log: (msg: string) => void
): Promise<void> {
  const plan = buildRemediationPlan(result);
  const removals = plan.actions.filter((a) => a.kind === "remove");
  const editable = plan.actions.filter((a) => a.kind !== "remove");

  if (editable.length === 0 && removals.length === 0) {
    vscode.window.showInformationMessage(
      "Fixly: nothing to apply — the last scan has no fixable vulnerabilities."
    );
    return;
  }

  if (editable.length > 0) {
    const uri = vscode.Uri.joinPath(folder.uri, "package.json");
    let doc: vscode.TextDocument;
    try {
      doc = await vscode.workspace.openTextDocument(uri);
    } catch {
      vscode.window.showErrorMessage(
        "Fixly: could not open package.json to apply the plan."
      );
      return;
    }

    const original = doc.getText();
    // core only reads plan.actions; feed it the file-editable actions so the
    // remove branch (which deletes malware) never runs here.
    const applied = applyRemediationPlan(original, { ...plan, actions: editable });

    for (const s of applied.skipped) {
      log(`Skipped (${s.package} not declared in package.json): ${s.command}`);
    }

    if (applied.text === original) {
      vscode.window.showInformationMessage(
        "Fixly: package.json already matches the remediation plan — no changes needed."
      );
    } else {
      // Preview before writing: side-by-side diff of current vs. proposed, then
      // a modal confirmation. Nothing touches disk until the user hits Apply.
      const proposedUri = preview.set(applied.text);
      await vscode.commands.executeCommand(
        "vscode.diff",
        uri,
        proposedUri,
        "package.json ↔ Proposed (Fixly)",
        { preview: true }
      );

      const n = applied.changes.length;
      const choice = await vscode.window.showInformationMessage(
        `Apply ${n} ${n === 1 ? "fix" : "fixes"} to package.json?`,
        { modal: true, detail: applied.changes.join("\n") },
        "Apply"
      );

      if (choice === "Apply") {
        // Re-read at apply time: the snapshot behind the preview can go stale
        // if package.json changed while the modal was up. Bail rather than
        // clobber edits the user never saw in the diff.
        const fresh = await vscode.workspace.openTextDocument(uri);
        const freshText = fresh.getText();
        if (freshText !== original) {
          vscode.window.showWarningMessage(
            "Fixly: package.json changed since the preview — nothing was written. Re-run \"Fixly: Apply Remediation Plan\"."
          );
          log("Apply aborted — package.json changed after the preview was shown.");
        } else {
          const edit = new vscode.WorkspaceEdit();
          const fullRange = new vscode.Range(
            fresh.positionAt(0),
            fresh.positionAt(freshText.length)
          );
          edit.replace(uri, fullRange, applied.text);
          await vscode.workspace.applyEdit(edit);
          await fresh.save();
          for (const c of applied.changes) log(`Applied: ${c}`);
          vscode.window.showInformationMessage(
            `Fixly: updated package.json (${n} ${n === 1 ? "change" : "changes"}). Run "npm install" to realize the fixes, then rescan.`
          );
        }
      } else {
        log("Remediation plan preview cancelled — package.json unchanged.");
      }
    }
  }

  if (removals.length > 0) {
    await warnAboutRemovals(removals);
    for (const r of removals) log(`Malware — remove by hand: ${r.command}`);
  }
}

/** Malware is never auto-removed: surface the uninstall commands to run. */
async function warnAboutRemovals(removals: RemediationAction[]): Promise<void> {
  const commands = removals.map((r) => r.command).join("\n");
  const pkgList = removals.map((r) => r.package).join(", ");
  const choice = await vscode.window.showWarningMessage(
    `Fixly: ${removals.length} malicious ${removals.length === 1 ? "package" : "packages"} (${pkgList}) must be removed by hand — Fixly does not edit files for malware. Uninstall commands:\n${commands}`,
    "Copy commands"
  );
  if (choice === "Copy commands") {
    await vscode.env.clipboard.writeText(commands);
    vscode.window.showInformationMessage(
      "Fixly: uninstall commands copied to clipboard."
    );
  }
}
