import type { OsvVuln } from "./osv";
import type { ScanVulnerability, Severity } from "./types";

// ---------------------------------------------------------------------------
// CVSS v3 base score calculator
// Spec: https://www.first.org/cvss/v3.1/specification-document
// ---------------------------------------------------------------------------
function cvssV3BaseScore(vector: string): number | null {
  const parts: Record<string, string> = {};
  for (const seg of vector.replace(/^CVSS:\d+\.\d+\//, "").split("/")) {
    const [k, v] = seg.split(":");
    if (k && v) parts[k] = v;
  }

  const S = parts["S"];
  const prMap: Record<string, number> =
    S === "C" ? { N: 0.85, L: 0.5, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };

  const AV = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as Record<string, number>)[parts["AV"]];
  const AC = ({ L: 0.77, H: 0.44 } as Record<string, number>)[parts["AC"]];
  const PR = prMap[parts["PR"]];
  const UI = ({ N: 0.85, R: 0.62 } as Record<string, number>)[parts["UI"]];
  const C  = ({ H: 0.56, L: 0.22, N: 0 } as Record<string, number>)[parts["C"]];
  const I  = ({ H: 0.56, L: 0.22, N: 0 } as Record<string, number>)[parts["I"]];
  const A  = ({ H: 0.56, L: 0.22, N: 0 } as Record<string, number>)[parts["A"]];

  if ([AV, AC, PR, UI, C, I, A].some((v) => v === undefined)) return null;

  const ISCBase = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact =
    S === "C"
      ? 7.52 * (ISCBase - 0.029) - 3.25 * Math.pow(ISCBase - 0.02, 15)
      : 6.42 * ISCBase;

  if (impact <= 0) return 0;

  const exploitability = 8.22 * AV * AC * PR * UI;
  const raw =
    S === "C"
      ? Math.min(1.08 * (impact + exploitability), 10)
      : Math.min(impact + exploitability, 10);

  return Math.ceil(raw * 10) / 10;
}

function severityFromScore(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

const SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MODERATE: "medium",
  MEDIUM: "medium",
  LOW: "low",
};

function readSeverityString(val: unknown): Severity | null {
  if (typeof val !== "string") return null;
  return SEVERITY_MAP[val.toUpperCase()] ?? null;
}

function extractSeverity(vuln: OsvVuln): Severity {
  // 1. Top-level database_specific.severity (GitHub Advisory Database)
  const s1 = readSeverityString(vuln.database_specific?.severity);
  if (s1) return s1;

  // 2. CVSS v3/v4 vector calculation
  const cvssEntry = vuln.severity?.find(
    (s) => s.type === "CVSS_V3" || s.type === "CVSS_V4"
  );
  if (cvssEntry?.score) {
    const score = cvssV3BaseScore(cvssEntry.score);
    if (score !== null) return severityFromScore(score);
  }

  // 3. Per-package database_specific.severity (some OSV entries put it here)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const affected of (vuln.affected ?? []) as any[]) {
    const s3 = readSeverityString(affected?.database_specific?.severity);
    if (s3) return s3;
    const s4 = readSeverityString(affected?.ecosystem_specific?.severity);
    if (s4) return s4;
  }

  return "unknown";
}

function extractFixedVersion(vuln: OsvVuln): string | null {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function extractCveId(vuln: OsvVuln): string | null {
  return vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? null;
}

function extractCvssVector(vuln: OsvVuln): string | null {
  return vuln.severity?.find((s) => s.type === "CVSS_V3")?.score ?? null;
}

function extractCvssScore(vuln: OsvVuln): number | null {
  const vector = extractCvssVector(vuln);
  return vector ? cvssV3BaseScore(vector) : null;
}

export function normalizeOsvResults(
  packageName: string,
  installedVersion: string,
  vulns: OsvVuln[]
): ScanVulnerability[] {
  return vulns.map((vuln) => ({
    osvId: vuln.id,
    cveId: extractCveId(vuln),
    package: packageName,
    installedVersion,
    fixedVersion: extractFixedVersion(vuln),
    severity: extractSeverity(vuln),
    cvssVector: extractCvssVector(vuln),
    cvssScore: extractCvssScore(vuln),
    title: vuln.summary ?? vuln.id,
    description: vuln.details ?? "",
    references: vuln.references?.map((r) => r.url) ?? [],
  }));
}
