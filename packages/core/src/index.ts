// @fixly/core — shared dependency-vulnerability scanner.
// Public API consumed by apps/web (remote GitHub scans) and the VS Code
// extension (local file scans).

export { runScan, scanProjectFiles, sortBySeverity } from "./scan";
export type { ScanProjectFilesInput } from "./scan";

// Pure URL parsing (also exported at @fixly/core/url for client-safe imports).
export { parseGitHubUrl } from "./github-url";
export type { GitHubRepo } from "./github-url";

export { fetchProject } from "./github";
export type { FetchResult, FetchedProject, FetchErrorCode } from "./github";

export { parseDependencies, resolveCheckVersion } from "./parse-packages";
export type { ParsedDependencies, ParseDependenciesOptions } from "./parse-packages";

export { queryOsvBatch, queryOsvPackage, osvQueryKey } from "./osv";
export type { OsvVuln, OsvQuery, OsvQueryResult } from "./osv";

export { normalizeOsvResults } from "./normalize";

export { enrichWithNvd, clearNvdCache } from "./nvd";
export type { NvdEnrichment, NvdEnrichmentOptions } from "./nvd";

// Package intelligence + verdicts (the engine behind check/vibecheck/MCP/guard).
export { checkPackage } from "./verdict";
export type {
  PackageVerdict,
  PackageSignals,
  VerdictLevel,
  CheckPackageOptions,
} from "./verdict";
export { enrichWithIntel, clearIntelCache, kevAgeDays, isNewlyExploited } from "./intel";
export type { IntelEnrichment } from "./intel";
export { fetchRegistryInfo, fetchLatestVersion, fetchDistTagVersion, clearRegistryCache } from "./registry";
export type { RegistryInfo } from "./registry";
export { findTyposquatTarget, editDistance } from "./typosquat";
export type { TyposquatMatch } from "./typosquat";
export { isPopularPackage, POPULAR_PACKAGES } from "./popular-packages";
export { scoreNameRisk, isNameModelAvailable, buildNameFeatures, resetNameModel } from "./name-model";
export type { NameRiskResult } from "./name-model";
export { computeGrade } from "./grade";
export type { ScanGrade, Grade, TopFix, GradeBreakdownEntry } from "./grade";

// Pure scan-diff helpers (also exported at @fixly/core/compare for client-safe
// imports).
export { findingKey, compareFindingKeys, countBySeverity } from "./compare";
export type { ScanDelta, SeverityCounts } from "./compare";

export {
  compareSemver,
  isVersionInOsvRanges,
  formatAffectedRanges,
} from "./matching";

export { clearScanCache } from "./cache";
export { fetchWithRetry, mapWithConcurrency } from "./http";
export type { RetryOptions } from "./http";

export type {
  Severity,
  DependencyType,
  DependencyEntry,
  VulnDataSource,
  NvdData,
  ScanVulnerability,
  ScanTarget,
  ScanError,
  ScanErrorCode,
  ScanResult,
} from "./types";
