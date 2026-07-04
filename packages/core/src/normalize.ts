import type { OsvVuln } from "./osv";
import type { DependencyType, ScanVulnerability, Severity } from "./types";
import { compareSemver, formatAffectedRanges, isVersionInOsvRanges } from "./matching";

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

  return roundUp1(raw);
}

// The official CVSS v3.1 "Roundup" (Appendix A) — compensates for binary
// floating-point so e.g. a raw 4.0000001 rounds to 4.0, not 4.1 (plain
// Math.ceil is the older v3.0 behavior and can flip a severity band).
function roundUp1(value: number): number {
  const int = Math.round(value * 100_000);
  if (int % 10_000 === 0) return int / 100_000;
  return (Math.floor(int / 10_000) + 1) / 10;
}

function severityFromScore(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// CVSS v4.0 — qualitative severity band (approximate)
//
// The official v4 base SCORE requires a ~270-entry MacroVector lookup table;
// reproducing it here would be disproportionate and error-prone. Instead we
// derive a conservative severity BAND from the base metrics — the same shape
// as a GitHub "database_specific.severity" qualitative rating (a band with no
// numeric score). This keeps v4-only advisories from silently degrading to
// "unknown" as CVSS v4 adoption grows, without fabricating a precise number.
// Uses v4's own metric keys (VC/VI/VA vulnerable-system impact, SC/SI/SA
// subsequent-system impact, plus the AT "attack requirements" metric).
// ---------------------------------------------------------------------------
function cvssV4Severity(vector: string): Severity | null {
  const parts: Record<string, string> = {};
  for (const seg of vector.replace(/^CVSS:\d+\.\d+\//, "").split("/")) {
    const [k, v] = seg.split(":");
    if (k && v) parts[k] = v;
  }

  const impactWeight = { H: 0.56, L: 0.22, N: 0 } as Record<string, number>;
  const VC = impactWeight[parts["VC"]];
  const VI = impactWeight[parts["VI"]];
  const VA = impactWeight[parts["VA"]];
  // Missing vulnerable-system impact keys → not a scorable v4 base vector.
  if (VC === undefined || VI === undefined || VA === undefined) return null;
  const SC = impactWeight[parts["SC"]] ?? 0;
  const SI = impactWeight[parts["SI"]] ?? 0;
  const SA = impactWeight[parts["SA"]] ?? 0;

  const AV = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as Record<string, number>)[parts["AV"]] ?? 0.85;
  const AC = ({ L: 0.77, H: 0.44 } as Record<string, number>)[parts["AC"]] ?? 0.77;
  const AT = ({ N: 0.85, P: 0.62 } as Record<string, number>)[parts["AT"]] ?? 0.85;
  const PR = ({ N: 0.85, L: 0.62, H: 0.27 } as Record<string, number>)[parts["PR"]] ?? 0.85;
  const UI = ({ N: 0.85, P: 0.62, A: 0.5 } as Record<string, number>)[parts["UI"]] ?? 0.85;

  const vulnIsc = 1 - (1 - VC) * (1 - VI) * (1 - VA);
  const subIsc = 1 - (1 - SC) * (1 - SI) * (1 - SA);
  const impact = 6.42 * vulnIsc + 3.0 * subIsc;
  if (impact <= 0) return "low";
  const exploitability = 8.22 * AV * AC * AT * PR * UI;
  const raw = Math.min(impact + exploitability, 10);
  return severityFromScore(Math.ceil(raw * 10) / 10);
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

  // 2. CVSS vector → severity. Prefer a v3 vector (precise base score); fall
  // back to a v4 vector (conservative qualitative band). Explicitly preferring
  // v3 also avoids a v4-listed-first entry shadowing a computable v3 score.
  const v3 = vuln.severity?.find((s) => s.type === "CVSS_V3");
  if (v3?.score) {
    const score = cvssV3BaseScore(v3.score);
    if (score !== null) return severityFromScore(score);
  }
  const v4 = vuln.severity?.find((s) => s.type === "CVSS_V4");
  if (v4?.score) {
    const sev = cvssV4Severity(v4.score);
    if (sev !== null) return sev;
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

function extractFixedVersion(vuln: OsvVuln, installedVersion: string): string | null {
  // An advisory can carry several fixed versions (one per affected range,
  // e.g. 3.x fixed in 3.2.2 AND 4.x fixed in 4.4.10). Recommend the smallest
  // fix that is an upgrade from the installed version; fall back to the
  // highest fix when none compares cleanly.
  const fixes: string[] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) fixes.push(event.fixed);
      }
    }
  }
  if (fixes.length === 0) return null;

  let bestUpgrade: string | null = null;
  let highest: string = fixes[0];
  for (const fix of fixes) {
    if ((compareSemver(fix, highest) ?? 0) > 0) highest = fix;
    if ((compareSemver(fix, installedVersion) ?? -1) > 0) {
      if (bestUpgrade === null || (compareSemver(fix, bestUpgrade) ?? 0) < 0) {
        bestUpgrade = fix;
      }
    }
  }
  return bestUpgrade ?? highest;
}

function extractCveId(vuln: OsvVuln): string | null {
  return vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? null;
}

function extractCvssVector(vuln: OsvVuln): string | null {
  // Surface a v3 vector if present, else the v4 vector — so the report shows
  // the real vector string even when we can't compute a precise v4 number.
  return (
    vuln.severity?.find((s) => s.type === "CVSS_V3")?.score ??
    vuln.severity?.find((s) => s.type === "CVSS_V4")?.score ??
    null
  );
}

function extractCvssScore(vuln: OsvVuln): number | null {
  // Only v3 yields a precise numeric base score; cvssV3BaseScore returns null
  // for a v4 vector (different metric keys), so v4-only findings keep a null
  // score and rely on the qualitative severity band — no fabricated number.
  const vector = vuln.severity?.find((s) => s.type === "CVSS_V3")?.score ?? null;
  return vector ? cvssV3BaseScore(vector) : null;
}

export function normalizeOsvResults(
  packageName: string,
  installedVersion: string,
  vulns: OsvVuln[],
  versionSource: "lockfile" | "range-minimum" = "lockfile",
  dependencyType: DependencyType = "dependencies"
): ScanVulnerability[] {
  return vulns.map((vuln) => ({
    osvId: vuln.id,
    cveId: extractCveId(vuln),
    package: packageName,
    installedVersion,
    fixedVersion: extractFixedVersion(vuln, installedVersion),
    severity: extractSeverity(vuln),
    cvssVector: extractCvssVector(vuln),
    cvssScore: extractCvssScore(vuln),
    affectedRanges: formatAffectedRanges(vuln, packageName),
    versionInRange: isVersionInOsvRanges(installedVersion, vuln, packageName),
    versionSource,
    dependencyType,
    sources: ["osv"],
    nvd: null,
    malicious: vuln.id.startsWith("MAL-"),
    knownExploited: false,
    epssScore: null,
    epssPercentile: null,
    kevDateAdded: null,
    pocCount: null,
    title: vuln.summary ?? vuln.id,
    description: vuln.details ?? "",
    references: safeReferenceUrls(vuln.references),
  }));
}

/**
 * OSV reference URLs are third-party data rendered as clickable links. Keep only
 * http(s) URLs so a crafted advisory can't smuggle a `javascript:`/`data:` URI
 * into an href (an XSS vector React does NOT sanitize). Filter at the source so
 * every consumer — web table, extension diagnostics, webview — is protected.
 */
function safeReferenceUrls(refs: OsvVuln["references"]): string[] {
  const urls: string[] = [];
  for (const r of refs ?? []) {
    if (typeof r?.url !== "string") continue;
    if (/^https?:\/\//i.test(r.url.trim())) urls.push(r.url);
  }
  return urls;
}
