import { parseGitHubUrl } from "./github-url";
import { fetchProject } from "./github";
import { parseDependencies, resolveCheckVersion } from "./parse-packages";
import { queryOsvBatch } from "./osv";
import { normalizeOsvResults } from "./normalize";
import { getCachedScan, setCachedScan, scanCacheKey } from "./cache";
import type {
  ScanResult,
  ScanTarget,
  ScanVulnerability,
  Severity,
} from "./types";

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

function emptyTarget(partial: Partial<ScanTarget> = {}): ScanTarget {
  return {
    owner: null,
    repo: null,
    branch: null,
    subpath: null,
    filesFound: [],
    filesMissing: [],
    ...partial,
  };
}

export interface ScanProjectFilesInput {
  /** Parsed package.json object. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageJson: any;
  /** Parsed package-lock.json object, if available. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageLock?: any | null;
  /** Display label for the scanned project (repo URL, folder name, etc.). */
  repo: string;
  /** What/where was scanned (files found, branch, owner/repo, subpath). */
  target?: ScanTarget;
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
  const target = input.target ?? emptyTarget();
  const base = { repo: input.repo, target, scannedAt, source: "osv" as const };

  const { dependencies, warnings } = parseDependencies(
    input.packageJson,
    input.packageLock ?? null
  );

  if (dependencies.length === 0) {
    return {
      ...base,
      dependencies,
      totalPackages: 0,
      resolvedPackages: 0,
      vulnerabilities: [],
      warnings,
      error: {
        code: "no_dependencies",
        message: "No dependencies or devDependencies were found in package.json.",
      },
    };
  }

  // Build the set of (name, concrete version) pairs to check against OSV.
  const checkable = dependencies
    .map((entry) => ({ name: entry.name, version: resolveCheckVersion(entry) }))
    .filter((q): q is { name: string; version: string } => q.version !== null);

  if (checkable.length === 0) {
    return {
      ...base,
      dependencies,
      totalPackages: dependencies.length,
      resolvedPackages: 0,
      vulnerabilities: [],
      warnings,
      error: {
        code: "no_dependencies",
        message: "No dependency versions could be resolved to check against OSV.",
      },
    };
  }

  let osv;
  try {
    osv = await queryOsvBatch(checkable);
  } catch (err) {
    return {
      ...base,
      dependencies,
      totalPackages: dependencies.length,
      resolvedPackages: checkable.length,
      vulnerabilities: [],
      warnings,
      error: {
        code: "osv_failed",
        message: `OSV query failed: ${err instanceof Error ? err.message : "Unknown error"}`,
      },
    };
  }

  const versionByName = new Map(checkable.map((q) => [q.name, q.version]));
  const vulnerabilities: ScanVulnerability[] = [];
  for (const [pkgName, vulns] of osv.results.entries()) {
    const version = versionByName.get(pkgName);
    if (!version) continue;
    vulnerabilities.push(...normalizeOsvResults(pkgName, version, vulns));
  }

  return {
    ...base,
    dependencies,
    totalPackages: dependencies.length,
    resolvedPackages: checkable.length,
    vulnerabilities: sortBySeverity(vulnerabilities),
    warnings: [...warnings, ...osv.warnings],
  };
}

/**
 * Scan a public GitHub repository: parse the URL, fetch its manifest files,
 * then run the shared {@link scanProjectFiles} pipeline. All failure modes are
 * returned as a structured {@link ScanResult.error}.
 */
export async function runScan(repoUrl: string): Promise<ScanResult> {
  const cacheKey = scanCacheKey(repoUrl);
  const cacheEnabled = process.env.FIXLY_DISABLE_SCAN_CACHE !== "1";
  if (cacheEnabled) {
    const cached = getCachedScan(cacheKey);
    if (cached) return cached;
  }

  const scannedAt = new Date().toISOString();
  const parsed = parseGitHubUrl(repoUrl);

  if (!parsed) {
    return {
      repo: repoUrl,
      target: emptyTarget(),
      scannedAt,
      source: "osv",
      dependencies: [],
      totalPackages: 0,
      resolvedPackages: 0,
      vulnerabilities: [],
      warnings: [],
      error: {
        code: "invalid_url",
        message:
          "Invalid GitHub URL. Use a public github.com repository URL, e.g. https://github.com/owner/repo.",
      },
    };
  }

  const fetched = await fetchProject(parsed.owner, parsed.repo, parsed.branch, parsed.subpath);

  if (!fetched.ok) {
    return {
      repo: repoUrl,
      target: emptyTarget({
        owner: parsed.owner,
        repo: parsed.repo,
        branch: parsed.branch ?? null,
        subpath: parsed.subpath ?? null,
        filesMissing: ["package.json"],
      }),
      scannedAt,
      source: "osv",
      dependencies: [],
      totalPackages: 0,
      resolvedPackages: 0,
      vulnerabilities: [],
      warnings: [],
      error: { code: fetched.code, message: fetched.message },
    };
  }

  const { packageJson, packageLock, branch, filesFound, filesMissing, warnings } =
    fetched.project;

  const result = await scanProjectFiles({
    packageJson,
    packageLock,
    repo: repoUrl,
    scannedAt,
    target: {
      owner: parsed.owner,
      repo: parsed.repo,
      branch,
      subpath: parsed.subpath ?? null,
      filesFound,
      filesMissing,
    },
  });

  // Prepend fetch-stage advisories (e.g. low rate limit) to the scan warnings.
  const merged = warnings.length
    ? { ...result, warnings: [...warnings, ...result.warnings] }
    : result;

  if (cacheEnabled && !merged.error) setCachedScan(cacheKey, merged);
  return merged;
}
