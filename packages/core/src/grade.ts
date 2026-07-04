// Fixly Score — one glanceable grade (A–F) for a whole scan, plus the three
// fixes that move it most. Pure function over a ScanResult: usable by the CLI
// (vibecheck), web report, extension, and badge alike.
//
// Philosophy: the grade must be *earned* arithmetic, not vibes — every point
// deducted traces to a finding, and the same result always grades the same.

import type { ScanResult, ScanVulnerability, Severity } from "./types";

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface GradeBreakdownEntry {
  reason: string;
  points: number;
}

export interface TopFix {
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  /** Why this fix is ranked here. */
  reason: string;
  /** Points recovered by applying it. */
  points: number;
  /** Copy-paste remediation, when a fixed version is known. */
  command: string | null;
}

export interface ScanGrade {
  grade: Grade;
  /** 0–100. */
  score: number;
  /** Every deduction, largest first. */
  breakdown: GradeBreakdownEntry[];
  /** The up-to-3 remediations that recover the most points. */
  topFixes: TopFix[];
  /** One-line verdict, human voice. */
  headline: string;
}

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 15,
  high: 6,
  medium: 2,
  low: 0.5,
  unknown: 1,
};
const KEV_PENALTY = 25; // on top of severity — exploited in the wild
const HIGH_EPSS_PENALTY = 5; // EPSS ≥ 0.1 without a KEV listing
const MALICIOUS_PENALTY = 100; // malware = automatic F

function penaltyFor(v: ScanVulnerability): { points: number; reason: string } {
  if (v.malicious) {
    return {
      points: MALICIOUS_PENALTY,
      reason: `${v.package}@${v.installedVersion} is a known MALICIOUS package (${v.osvId})`,
    };
  }
  let points = SEVERITY_PENALTY[v.severity];
  let qualifier = v.severity as string;
  if (v.knownExploited) {
    points += KEV_PENALTY;
    qualifier += ", exploited in the wild (CISA KEV)";
  } else if (v.epssScore !== null && v.epssScore >= 0.1) {
    points += HIGH_EPSS_PENALTY;
    qualifier += `, ${(v.epssScore * 100).toFixed(0)}% EPSS exploit probability`;
  }
  return {
    points,
    reason: `${v.package}@${v.installedVersion}: ${v.cveId ?? v.osvId} (${qualifier})`,
  };
}

function toGrade(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

function buildHeadline(grade: Grade, result: ScanResult, hasMalware: boolean): string {
  const n = result.vulnerabilities.length;
  const pkgs = result.totalPackages;
  if (hasMalware) return `F — a known-malicious package is installed. Stop and remove it before anything else.`;
  switch (grade) {
    case "A":
      return n === 0
        ? `A — ${pkgs} packages checked, nothing to fix. Ship it.`
        : `A — ${pkgs} packages checked, only minor noise. Ship it.`;
    case "B":
      return `B — solid, but ${n} findings deserve a look before you ship.`;
    case "C":
      return `C — ${n} findings, some serious. Half an hour of upgrades would pay off.`;
    case "D":
      return `D — ${n} findings including high-priority ones. Your dependencies need attention today.`;
    default:
      return `F — ${n} findings with real exploitation risk. Fix the top three immediately.`;
  }
}

/** Grade a completed scan. Deterministic; safe on error results (grades what was found). */
export function computeGrade(result: ScanResult): ScanGrade {
  const breakdown: GradeBreakdownEntry[] = [];
  const byPackage = new Map<string, { points: number; vuln: ScanVulnerability }>();
  let total = 0;
  let hasMalware = false;

  for (const v of result.vulnerabilities) {
    const { points, reason } = penaltyFor(v);
    total += points;
    if (v.malicious) hasMalware = true;
    breakdown.push({ reason, points });
    // Rank remediations by recoverable points per package@version.
    const key = `${v.package}@${v.installedVersion}`;
    const prev = byPackage.get(key);
    if (prev) {
      prev.points += points;
      if (points > penaltyFor(prev.vuln).points) prev.vuln = v;
    } else {
      byPackage.set(key, { points, vuln: v });
    }
  }

  breakdown.sort((a, b) => b.points - a.points);
  const score = Math.max(0, Math.round((100 - total) * 10) / 10);
  const grade = toGrade(score);

  const topFixes: TopFix[] = [...byPackage.values()]
    .sort((a, b) => b.points - a.points)
    .slice(0, 3)
    .map(({ points, vuln }) => ({
      package: vuln.package,
      installedVersion: vuln.installedVersion,
      fixedVersion: vuln.fixedVersion,
      reason: vuln.malicious
        ? `known malicious package — remove it`
        : vuln.knownExploited
          ? `${vuln.cveId ?? vuln.osvId} is exploited in the wild`
          : `worst finding: ${vuln.cveId ?? vuln.osvId} (${vuln.severity})`,
      points,
      command: vuln.malicious
        ? `npm uninstall ${vuln.package}`
        : vuln.fixedVersion && vuln.dependencyType !== "transitive"
          ? `npm install ${vuln.package}@${vuln.fixedVersion}`
          : vuln.fixedVersion
            ? `npm update ${vuln.package} # transitive — or add an "overrides" entry for ${vuln.package}@${vuln.fixedVersion}`
            : null,
    }));

  return { grade, score, breakdown, topFixes, headline: buildHeadline(grade, result, hasMalware) };
}
