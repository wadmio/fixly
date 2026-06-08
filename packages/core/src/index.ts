// @fixly/core — shared dependency-vulnerability scanner.
// Public API consumed by apps/web (remote GitHub scans) and the VS Code
// extension (local file scans).

export { runScan, scanProjectFiles, sortBySeverity } from "./scan";
export type { ScanProjectFilesInput } from "./scan";

export { parseGitHubUrl, fetchProjectFiles } from "./github";
export type { GitHubRepo, ProjectFiles } from "./github";

export { parsePackages } from "./parse-packages";
export type { ParsedPackages } from "./parse-packages";

export { queryOsvBatch } from "./osv";
export type { OsvVuln, OsvQueryResult } from "./osv";

export { normalizeOsvResults } from "./normalize";

export type {
  Severity,
  PackageEntry,
  ScanVulnerability,
  ScanResult,
} from "./types";
