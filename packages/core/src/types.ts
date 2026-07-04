export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type DependencyType = "dependencies" | "devDependencies";

/**
 * A single direct dependency declared in package.json, with its resolution
 * status. `installedVersion` is the exact version from package-lock.json when
 * available, otherwise null — we never invent an installed version.
 */
export interface DependencyEntry {
  name: string;
  /** The version range as written in package.json (e.g. "^1.2.3"). */
  requestedVersion: string;
  /** Exact version from package-lock.json, or null if no lock entry exists. */
  installedVersion: string | null;
  dependencyType: DependencyType;
  /** The manifest the dependency was declared in. */
  sourceFile: "package.json";
}

export interface ScanVulnerability {
  osvId: string;
  cveId: string | null;
  package: string;
  /** The concrete version that was checked against OSV (lock version, or the
   *  resolved minimum of the requested range when no lock file is present). */
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  cvssVector: string | null;
  cvssScore: number | null;
  /** Affected version ranges from OSV, rendered for display (e.g. ">=0 <4.17.12"). */
  affectedRanges: string[];
  /** Whether `installedVersion` falls inside an OSV affected range, verified
   *  locally. null when the ranges could not be evaluated (limited confidence). */
  versionInRange: boolean | null;
  /** How the checked version was obtained: an exact `package-lock.json` entry,
   *  or the minimum of the declared range when no lock file was present
   *  (the latter is approximate). */
  versionSource: "lockfile" | "range-minimum";
  title: string;
  description: string;
  references: string[];
}

export type ScanErrorCode =
  | "invalid_url"
  | "repo_not_found"
  | "private_repo"
  | "branch_not_found"
  | "no_package_json"
  | "no_dependencies"
  | "rate_limited"
  | "osv_failed"
  | "github_error";

export interface ScanError {
  code: ScanErrorCode;
  message: string;
}

/** What was scanned and which manifest files were located. */
export interface ScanTarget {
  owner: string | null;
  repo: string | null;
  /** Branch actually used (resolved default branch, or the requested branch). */
  branch: string | null;
  /** Subfolder scanned, if the URL pointed at one. */
  subpath: string | null;
  /** e.g. ["package.json", "package-lock.json"]. */
  filesFound: string[];
  /** e.g. ["package-lock.json"]. */
  filesMissing: string[];
}

export interface ScanResult {
  /** Display label: the repo URL (web) or the folder name (extension). */
  repo: string;
  target: ScanTarget;
  scannedAt: string;
  source: "osv";
  /** Every direct dependency found, with resolution status. */
  dependencies: DependencyEntry[];
  /** Number of direct dependencies declared (dependencies.length). */
  totalPackages: number;
  /** Number of dependencies with a concrete version checked against OSV. */
  resolvedPackages: number;
  vulnerabilities: ScanVulnerability[];
  /** Non-fatal issues (missing lockfile, unresolved versions, partial OSV data). */
  warnings: string[];
  /** Set when the scan could not complete; other fields will be empty/zero. */
  error?: ScanError;
}
