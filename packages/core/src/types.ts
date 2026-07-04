export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export type DependencyType = "dependencies" | "devDependencies" | "transitive";

/** Where a finding's vulnerability data came from. */
export type VulnDataSource = "osv" | "nvd";

/**
 * A single dependency to check. Direct entries come from package.json
 * (`dependencies`/`devDependencies`); `transitive` entries are discovered in
 * the package-lock.json tree with exact installed versions. For direct
 * entries, `installedVersion` is the exact version from package-lock.json when
 * available, otherwise null — we never invent an installed version.
 */
export interface DependencyEntry {
  name: string;
  /** The version range as written in package.json (e.g. "^1.2.3"). For
   *  transitive entries this is the exact locked version. */
  requestedVersion: string;
  /** Exact version from package-lock.json, or null if no lock entry exists. */
  installedVersion: string | null;
  dependencyType: DependencyType;
  /** The manifest the dependency was declared/discovered in. */
  sourceFile: "package.json" | "package-lock.json";
}

/** CVSS data cross-referenced from the National Vulnerability Database. */
export interface NvdData {
  cvssScore: number | null;
  cvssVector: string | null;
  severity: Severity | null;
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
  /** Whether the vulnerable package is a direct dependency (declared in
   *  package.json) or was discovered in the lock file tree (`transitive`). */
  dependencyType: DependencyType;
  /** Which databases reported/confirmed this finding. Always includes "osv";
   *  "nvd" is added when the CVE was cross-referenced against NVD. */
  sources: VulnDataSource[];
  /** NVD's independent CVSS assessment for the CVE, when cross-referenced. */
  nvd: NvdData | null;
  /** True when this is a malicious-package advisory (OSV `MAL-` record) —
   *  the package itself is malware, not merely buggy. */
  malicious: boolean;
  /** True when the CVE is in CISA's Known Exploited Vulnerabilities catalog
   *  (confirmed exploitation in the wild — top remediation priority). */
  knownExploited: boolean;
  /** EPSS probability (0–1) the CVE is exploited in the next 30 days. */
  epssScore: number | null;
  /** EPSS percentile (0–1) relative to all scored CVEs. */
  epssPercentile: number | null;
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
  /** "osv+nvd" when at least one finding was cross-referenced against NVD. */
  source: "osv" | "osv+nvd";
  /** Every dependency found (direct + transitive), with resolution status. */
  dependencies: DependencyEntry[];
  /** Number of dependencies scanned (dependencies.length). */
  totalPackages: number;
  /** Direct dependencies declared in package.json. */
  directPackages: number;
  /** Unique package@version pairs discovered in the lock file tree. */
  transitivePackages: number;
  /** Number of dependencies with a concrete version checked against OSV. */
  resolvedPackages: number;
  vulnerabilities: ScanVulnerability[];
  /** Non-fatal issues (missing lockfile, unresolved versions, partial OSV data). */
  warnings: string[];
  /** Set when the scan could not complete; other fields will be empty/zero. */
  error?: ScanError;
}
