import { parseGitHubUrl, fetchProjectFiles } from "./github";
import { parsePackages } from "./parse-packages";
import { queryOsvBatch } from "./osv";
import { normalizeOsvResults } from "./normalize";
import type { ScanResult, ScanVulnerability, Severity } from "./types";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

/** Return a new array of vulnerabilities ordered critical → unknown. */
export function sortBySeverity(
  vulnerabilities: ScanVulnerability[]
): ScanVulnerability[] {
  return [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
}

export interface ScanProjectFilesInput {
  /** Parsed package.json object. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageJson: any;
  /** Parsed package-lock.json object, if available. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageLock?: any | null;
  /** Label for the scanned project (repo URL, folder name, etc.). */
  repo: string;
  /** Override the scan timestamp (defaults to now). */
  scannedAt?: string;
}

/**
 * Core scan: resolve dependencies from already-loaded manifest files, query
 * OSV, and return a normalized, severity-sorted report. Shared by the web
 * scanner (remote GitHub files) and the VS Code extension (local files).
 */
export async function scanProjectFiles(
  input: ScanProjectFilesInput
): Promise<ScanResult> {
  const scannedAt = input.scannedAt ?? new Date().toISOString();
  const base = { repo: input.repo, scannedAt, source: "osv" as const };

  const { packages, warnings } = parsePackages(
    input.packageJson,
    input.packageLock ?? null
  );

  if (packages.length === 0) {
    return {
      ...base,
      totalPackages: 0,
      vulnerabilities: [],
      warnings,
      error: "No resolvable packages found in package.json.",
    };
  }

  let osv;
  try {
    osv = await queryOsvBatch(packages);
  } catch (err) {
    return {
      ...base,
      totalPackages: packages.length,
      vulnerabilities: [],
      warnings,
      error: `OSV query failed: ${err instanceof Error ? err.message : "Unknown error"}`,
    };
  }

  const vulnerabilities: ScanVulnerability[] = [];
  for (const [pkgName, vulns] of osv.results.entries()) {
    const pkg = packages.find((p) => p.name === pkgName);
    if (!pkg) continue;
    vulnerabilities.push(...normalizeOsvResults(pkgName, pkg.version, vulns));
  }

  return {
    ...base,
    totalPackages: packages.length,
    vulnerabilities: sortBySeverity(vulnerabilities),
    warnings: [...warnings, ...osv.warnings],
  };
}

/**
 * Scan a public GitHub repository: parse the URL, fetch its manifest files,
 * then run the shared {@link scanProjectFiles} pipeline.
 */
export async function runScan(repoUrl: string): Promise<ScanResult> {
  const scannedAt = new Date().toISOString();
  const base = { repo: repoUrl, scannedAt, source: "osv" as const };

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return {
      ...base,
      totalPackages: 0,
      vulnerabilities: [],
      warnings: [],
      error:
        "Invalid GitHub URL. Please use a public github.com repository URL (e.g. https://github.com/owner/repo).",
    };
  }

  const { owner, repo, branch, subpath } = parsed;
  const { packageJson, packageLock, error } = await fetchProjectFiles(
    owner,
    repo,
    branch,
    subpath
  );

  if (!packageJson) {
    const msg =
      error === "private"
        ? `${owner}/${repo} is private or requires authentication. Only public repositories are supported.`
        : `No package.json found in ${owner}/${repo}. This may not be a Node.js project, or the file may be in a subdirectory.`;
    return {
      ...base,
      totalPackages: 0,
      vulnerabilities: [],
      warnings: [],
      error: msg,
    };
  }

  return scanProjectFiles({ packageJson, packageLock, repo: repoUrl, scannedAt });
}
