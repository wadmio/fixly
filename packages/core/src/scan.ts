import { parseGitHubUrl } from "./github-url";
import { fetchProject } from "./github";
import { parseDependencies, resolveCheckVersion } from "./parse-packages";
import { queryOsvBatch, osvQueryKey } from "./osv";
import { normalizeOsvResults } from "./normalize";
import { enrichWithNvd } from "./nvd";
import { enrichWithIntel } from "./intel";
import { getCachedScan, setCachedScan, scanCacheKey } from "./cache";
import type {
  DependencyType,
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

/**
 * Return a new array of vulnerabilities ordered by severity (critical →
 * unknown), then by package name within the same severity.
 */
export function sortBySeverity(
  vulnerabilities: ScanVulnerability[]
): ScanVulnerability[] {
  return [...vulnerabilities].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.package.localeCompare(b.package);
  });
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
  /** Also scan transitive packages from the lock file tree (default true). */
  includeTransitive?: boolean;
  /** Cross-reference CVEs against NVD (default true; best-effort — rate
   *  limits and timeouts degrade to warnings, never failures). Also disabled
   *  globally via FIXLY_DISABLE_NVD=1. */
  nvd?: boolean;
  /** Enrich findings with exploit intelligence — CISA KEV known-exploited
   *  flags + EPSS exploit-probability scores (default true; best-effort).
   *  Also disabled globally via FIXLY_DISABLE_INTEL=1. */
  intel?: boolean;
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
    input.packageLock ?? null,
    { includeTransitive: input.includeTransitive ?? true }
  );

  const directPackages = dependencies.filter((d) => d.dependencyType !== "transitive").length;
  const transitivePackages = dependencies.length - directPackages;
  const counts = { directPackages, transitivePackages };

  if (dependencies.length === 0) {
    return {
      ...base,
      dependencies,
      totalPackages: 0,
      ...counts,
      resolvedPackages: 0,
      vulnerabilities: [],
      warnings,
      error: {
        code: "no_dependencies",
        message: "No dependencies or devDependencies were found in package.json.",
      },
    };
  }

  // Build the set of (name, concrete version) pairs to check against OSV,
  // keyed by name@version — the same package can appear at several versions in
  // a lock file tree. `source` records whether the version came from an exact
  // lock entry or the resolved minimum of a declared range (approximate).
  type Checkable = {
    name: string;
    version: string;
    source: "lockfile" | "range-minimum";
    dependencyType: DependencyType;
  };
  const checkableByKey = new Map<string, Checkable>();
  for (const entry of dependencies) {
    const version = resolveCheckVersion(entry);
    if (version === null) continue;
    const item: Checkable = {
      name: entry.name,
      version,
      source: entry.installedVersion ? "lockfile" : "range-minimum",
      dependencyType: entry.dependencyType,
    };
    const key = osvQueryKey(item);
    // Direct entries were parsed first and win over a transitive duplicate.
    if (!checkableByKey.has(key)) checkableByKey.set(key, item);
  }
  const checkable = [...checkableByKey.values()];

  if (checkable.length === 0) {
    return {
      ...base,
      dependencies,
      totalPackages: dependencies.length,
      ...counts,
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
      ...counts,
      resolvedPackages: checkable.length,
      vulnerabilities: [],
      warnings,
      error: {
        code: "osv_failed",
        message: `OSV query failed: ${err instanceof Error ? err.message : "Unknown error"}`,
      },
    };
  }

  const vulnerabilities: ScanVulnerability[] = [];
  for (const [key, vulns] of osv.results.entries()) {
    const item = checkableByKey.get(key);
    if (!item) continue;
    vulnerabilities.push(
      ...normalizeOsvResults(item.name, item.version, vulns, item.source, item.dependencyType)
    );
  }

  let sorted = sortBySeverity(vulnerabilities);
  let source: ScanResult["source"] = "osv";
  const nvdWarnings: string[] = [];

  // Second-source verification: cross-reference CVEs against NVD (best-effort).
  const nvdEnabled = (input.nvd ?? true) && process.env.FIXLY_DISABLE_NVD !== "1";
  if (nvdEnabled && sorted.length > 0) {
    const enrichment = await enrichWithNvd(sorted);
    sorted = enrichment.vulnerabilities;
    nvdWarnings.push(...enrichment.warnings);
    if (enrichment.enrichedCount > 0) source = "osv+nvd";
  }

  // Exploit intelligence: CISA KEV + EPSS on every CVE (best-effort).
  const intelEnabled = (input.intel ?? true) && process.env.FIXLY_DISABLE_INTEL !== "1";
  if (intelEnabled && sorted.length > 0) {
    const intel = await enrichWithIntel(sorted);
    sorted = intel.vulnerabilities;
    nvdWarnings.push(...intel.warnings);
  }

  return {
    ...base,
    source,
    dependencies,
    totalPackages: dependencies.length,
    ...counts,
    resolvedPackages: checkable.length,
    vulnerabilities: sorted,
    warnings: [...warnings, ...osv.warnings, ...nvdWarnings],
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
      directPackages: 0,
      transitivePackages: 0,
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
      directPackages: 0,
      transitivePackages: 0,
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
