export type Severity = "critical" | "high" | "medium" | "low" | "unknown";

export interface PackageEntry {
  name: string;
  version: string;
  isDev: boolean;
}

export interface ScanVulnerability {
  osvId: string;
  cveId: string | null;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  cvssVector: string | null;
  cvssScore: number | null;
  title: string;
  description: string;
  references: string[];
}

export interface ScanResult {
  repo: string;
  scannedAt: string;
  totalPackages: number;
  vulnerabilities: ScanVulnerability[];
  source: "osv";
  /** Non-fatal issues surfaced during the scan (missing lockfile, unresolved versions, partial OSV data). */
  warnings: string[];
  /** Set when the scan could not complete; vulnerabilities will be empty. */
  error?: string;
}
