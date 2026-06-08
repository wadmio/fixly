import * as vscode from "vscode";
import { scanProjectFiles, type ScanResult } from "@fixly/core";

export type ScanOutcome =
  | { ok: true; result: ScanResult }
  | { ok: false; error: string };

async function readJson(
  uri: vscode.Uri,
  log: (msg: string) => void
): Promise<unknown | null> {
  try {
    const bytes = await vscode.workspace.fs.readFile(uri);
    const parsed = JSON.parse(Buffer.from(bytes).toString("utf-8"));
    log(`Loaded ${uri.fsPath}`);
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Scan the first open workspace folder: read its package.json /
 * package-lock.json and run the shared @fixly/core pipeline against OSV.
 */
export async function scanWorkspace(
  log: (msg: string) => void
): Promise<ScanOutcome> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return {
      ok: false,
      error: "No folder is open. Open a Node.js project folder and try again.",
    };
  }

  const packageJson = await readJson(
    vscode.Uri.joinPath(folder.uri, "package.json"),
    log
  );
  if (!packageJson) {
    return {
      ok: false,
      error: `No readable package.json found in "${folder.name}". This does not look like a Node.js project.`,
    };
  }

  const packageLock = await readJson(
    vscode.Uri.joinPath(folder.uri, "package-lock.json"),
    log
  );
  if (!packageLock) {
    log("No package-lock.json found; resolving versions from package.json ranges.");
  }

  log("Querying OSV…");
  const result = await scanProjectFiles({
    packageJson,
    packageLock,
    repo: folder.name,
  });
  log(
    `Scan complete: ${result.vulnerabilities.length} vulnerabilities across ${result.totalPackages} packages.`
  );

  return { ok: true, result };
}
