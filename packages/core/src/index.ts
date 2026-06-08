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
export type { ParsedDependencies } from "./parse-packages";

export { queryOsvBatch } from "./osv";
export type { OsvVuln, OsvQuery, OsvQueryResult } from "./osv";

export { normalizeOsvResults } from "./normalize";

export type {
  Severity,
  DependencyType,
  DependencyEntry,
  ScanVulnerability,
  ScanTarget,
  ScanError,
  ScanErrorCode,
  ScanResult,
} from "./types";
