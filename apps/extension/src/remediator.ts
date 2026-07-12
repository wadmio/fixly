// The in-editor remediation engine: apply the fix plan to package.json as a
// WorkspaceEdit (visible in the open editor and undoable with Ctrl+Z), run
// `npm install` to realize the lock file, then re-scan to VERIFY the findings
// are gone before "remediated" is ever claimed. Reports the measured MTTR
// (change detected → fix verified) — the same contract as `fixly daemon`,
// living where vibecoders actually work.

import { spawn } from "node:child_process";
import * as vscode from "vscode";
import {
  applyRemediationPlan,
  buildRemediationPlan,
  computeGrade,
  findingKey,
  type RemediationPlan,
  type ScanResult,
  type ScanVulnerability,
} from "@fixly/core";
import { scanWorkspace } from "./scanner";

export interface EditorRemediationOutcome {
  /** package.json was rewritten (as an undoable WorkspaceEdit). */
  applied: boolean;
  /** npm install ran and succeeded. */
  installed: boolean;
  /** The re-scan confirmed the plan's findings are gone. */
  verified: boolean;
  plan: RemediationPlan;
  changes: string[];
  /** Detection → verified, in ms. null when nothing was applied. */
  mttrMs: number | null;
  verifyResult: ScanResult | null;
  after: { grade: string; score: number } | null;
  failure: string | null;
}

function runNpmInstall(cwd: string): Promise<{ code: number; output: string }> {
  // npm is a .cmd shim on Windows, which requires a shell. Output is captured
  // (the Fixly output channel gets the tail on failure), never streamed.
  const windows = process.platform === "win32";
  return new Promise((resolve) => {
    const child = windows
      ? spawn("npm install --no-audit --no-fund", {
          cwd,
          stdio: ["ignore", "pipe", "pipe"],
          shell: true,
        })
      : spawn("npm", ["install", "--no-audit", "--no-fund"], {
          cwd,
          stdio: ["ignore", "pipe", "pipe"],
        });
    let output = "";
    child.stdout?.on("data", (d: Buffer) => (output += String(d)));
    child.stderr?.on("data", (d: Buffer) => (output += String(d)));
    child.on("close", (code) => resolve({ code: code ?? 1, output }));
    child.on("error", (err) => resolve({ code: 1, output: err.message }));
  });
}

/**
 * Run the full remediation loop for a scan. `triggeredBy` are the findings
 * whose removal defines "verified" (pass all fixable findings to fix
 * everything). The caller is responsible for suppressing file-watcher
 * re-entrancy while this runs.
 */
export async function remediateInEditor(
  folder: vscode.WorkspaceFolder,
  result: ScanResult,
  triggeredBy: ScanVulnerability[],
  detectedAt: number,
  log: (msg: string) => void
): Promise<EditorRemediationOutcome> {
  const plan = buildRemediationPlan(result);
  const outcome: EditorRemediationOutcome = {
    applied: false,
    installed: false,
    verified: false,
    plan,
    changes: [],
    mttrMs: null,
    verifyResult: null,
    after: null,
    failure: null,
  };

  if (plan.actions.length === 0) {
    outcome.failure = "no published fix exists yet for the detected findings";
    return outcome;
  }

  // 1. Rewrite package.json as a WorkspaceEdit — visible live in the editor
  //    if the file is open, and a single Ctrl+Z away from undone.
  const manifestUri = vscode.Uri.joinPath(folder.uri, "package.json");
  try {
    const document = await vscode.workspace.openTextDocument(manifestUri);
    const applied = applyRemediationPlan(document.getText(), plan);
    const fullRange = new vscode.Range(
      document.positionAt(0),
      document.positionAt(document.getText().length)
    );
    const edit = new vscode.WorkspaceEdit();
    edit.replace(manifestUri, fullRange, applied.text);
    const ok = await vscode.workspace.applyEdit(edit);
    if (!ok) throw new Error("workspace edit was rejected");
    await document.save();
    outcome.applied = true;
    outcome.changes = applied.changes;
    for (const change of applied.changes) log(`Remediation: ${change}`);
  } catch (err) {
    outcome.failure = `could not rewrite package.json: ${err instanceof Error ? err.message : String(err)}`;
    return outcome;
  }

  // 2. Realize the manifest change in the lock file / node_modules.
  log("Remediation: running npm install…");
  const install = await runNpmInstall(folder.uri.fsPath);
  if (install.code !== 0) {
    const tail = install.output.trim().split("\n").slice(-5).join("\n");
    outcome.failure = `npm install failed (exit ${install.code}): ${tail}`;
    return outcome;
  }
  outcome.installed = true;

  // 3. Verify — the same scanner that found the problem confirms it is gone.
  log("Remediation: verifying with a re-scan…");
  const verify = await scanWorkspace(log);
  if (!verify.ok) {
    outcome.failure = `verify scan failed: ${verify.error}`;
    return outcome;
  }
  if (verify.result.error) {
    outcome.failure = `verify scan failed: ${verify.result.error.message}`;
    return outcome;
  }
  outcome.verifyResult = verify.result;
  const afterGrade = computeGrade(verify.result);
  outcome.after = { grade: afterGrade.grade, score: afterGrade.score };

  // Verified when every triggering finding the plan claimed to fix is gone
  // (unfixable findings were never promised and don't fail verification).
  const planResolves = new Set(plan.actions.flatMap((a) => a.resolves));
  const remainingKeys = new Set(verify.result.vulnerabilities.map(findingKey));
  outcome.verified = triggeredBy
    .filter((v) => planResolves.has(v.osvId))
    .every((v) => !remainingKeys.has(findingKey(v)));
  if (!outcome.verified) {
    outcome.failure = "verify scan still reports some of the findings";
  }
  outcome.mttrMs = Date.now() - detectedAt;
  return outcome;
}
