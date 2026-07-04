// Response shaping — the most important design decision in this server.
//
// An AI coding agent's context window is a scarce, shared resource. Handing it
// 267 raw findings poisons the conversation it was supposed to protect. Every
// tool response here is a compact, verdict-shaped object: the decision, the
// reasons, the fix — and nothing else. (Full reports belong to the CLI/web.)

import type { PackageVerdict, ScanResult, ScanGrade } from "@fixly/core";
import { countBySeverity } from "@fixly/core";

const MAX_REASONS = 5;
const MAX_FIXES = 5;

export interface CompactVerdict {
  package: string;
  evaluatedVersion: string | null;
  verdict: "safe" | "caution" | "block";
  summary: string;
  reasons: string[];
  didYouMean: string | null;
  fixCommand: string | null;
  signals: {
    exists: boolean | null;
    popular: boolean;
    ageDays: number | null;
    weeklyDownloads: number | null;
    runsInstallScripts: boolean | null;
    malicious: boolean;
    knownExploitedCves: string[];
    vulnerabilities: Record<string, number>;
  };
  warnings: string[];
}

export function compactVerdict(v: PackageVerdict): CompactVerdict {
  // The best single remediation for a vulnerable-but-legit package: the
  // highest fixed version among its worst findings.
  const fix = v.vulnerabilities.find((f) => f.fixedVersion)?.fixedVersion ?? null;
  return {
    package: v.package,
    evaluatedVersion: v.evaluatedVersion,
    verdict: v.verdict,
    summary: v.summary,
    reasons: v.reasons.slice(0, MAX_REASONS),
    didYouMean: v.signals.typosquatOf,
    fixCommand:
      v.verdict !== "safe" && fix ? `npm install ${v.package}@${fix}` : null,
    signals: {
      exists: v.signals.exists,
      popular: v.signals.popular,
      ageDays: v.signals.ageDays,
      weeklyDownloads: v.signals.weeklyDownloads,
      runsInstallScripts: v.signals.hasInstallScripts,
      malicious: v.signals.maliciousIds.length > 0,
      knownExploitedCves: v.signals.knownExploitedCves,
      vulnerabilities: v.signals.vulnerabilityCounts,
    },
    warnings: v.warnings,
  };
}

export interface CompactScan {
  project: string;
  grade: string;
  score: number;
  headline: string;
  packages: { total: number; direct: number; transitive: number };
  findings: { total: number; bySeverity: Record<string, number> };
  maliciousPackages: string[];
  exploitedInTheWild: string[];
  topFixes: Array<{
    package: string;
    installedVersion: string;
    fixedVersion: string | null;
    command: string | null;
    reason: string;
  }>;
  warnings: string[];
  note: string;
}

export function compactScan(result: ScanResult, grade: ScanGrade): CompactScan {
  const malicious = [
    ...new Set(
      result.vulnerabilities
        .filter((v) => v.malicious)
        .map((v) => `${v.package}@${v.installedVersion}`)
    ),
  ];
  const kev = [
    ...new Set(
      result.vulnerabilities
        .filter((v) => v.knownExploited && v.cveId)
        .map((v) => `${v.package}: ${v.cveId}`)
    ),
  ];
  return {
    project: result.repo,
    grade: grade.grade,
    score: grade.score,
    headline: grade.headline,
    packages: {
      total: result.totalPackages,
      direct: result.directPackages,
      transitive: result.transitivePackages,
    },
    findings: {
      total: result.vulnerabilities.length,
      bySeverity: countBySeverity(result.vulnerabilities),
    },
    maliciousPackages: malicious,
    exploitedInTheWild: kev,
    topFixes: grade.topFixes.slice(0, MAX_FIXES).map((f) => ({
      package: f.package,
      installedVersion: f.installedVersion,
      fixedVersion: f.fixedVersion,
      command: f.command,
      reason: f.reason,
    })),
    warnings: result.warnings,
    note:
      result.vulnerabilities.length > grade.topFixes.length
        ? "Compact summary by design — run `npx fixly scan` for every finding."
        : "Complete.",
  };
}
