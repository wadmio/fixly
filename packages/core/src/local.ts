// Local-project scanning for Node-based surfaces (CLI, MCP server). Kept out
// of the root barrel and exported at @fixly/core/node because it imports
// node:fs — the root stays importable in any server runtime, and browser-safe
// subpaths (/url, /compare) stay untouched.

import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { scanProjectFiles } from "./scan";
import type { ScanResult } from "./types";

async function readJsonFile(path: string): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error(`Could not parse ${path} — is it valid JSON?`);
  }
}

export interface LocalScanOptions {
  includeTransitive?: boolean;
}

/**
 * Scan the npm project rooted at `dir` (package.json required,
 * package-lock.json used when present) through the shared pipeline. Throws a
 * friendly error when the directory is not an npm project.
 */
export async function scanLocalProject(
  dir: string,
  options: LocalScanOptions = {}
): Promise<ScanResult> {
  const root = resolve(dir);
  const packageJson = await readJsonFile(join(root, "package.json"));
  if (packageJson === null) {
    throw new Error(
      `No package.json in ${root} — point fixly at an npm project directory.`
    );
  }
  const packageLock = await readJsonFile(join(root, "package-lock.json"));

  return scanProjectFiles({
    packageJson,
    packageLock,
    includeTransitive: options.includeTransitive,
    repo: basename(root),
    target: {
      owner: null,
      repo: basename(root),
      branch: null,
      subpath: null,
      filesFound: packageLock ? ["package.json", "package-lock.json"] : ["package.json"],
      filesMissing: packageLock ? [] : ["package-lock.json"],
    },
  });
}
