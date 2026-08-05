// Fixly Remediation Engine — turns a completed scan into an ordered, advice-only
// fix plan plus a Grade Forecast: the exact Fixly Score the project would earn
// if the plan were applied. Pure functions over a ScanResult (no network, no
// fs), so every surface — CLI `fixly fix`, the web report, the VS Code panel —
// shows the same plan for the same scan. Fixly analyzes and verifies, never
// modifies: the plan's commands and overrides are text for the USER (or their
// AI agent) to apply — nothing here writes files.
//
// Same philosophy as the grade: earned arithmetic, not vibes. The forecast is
// computed by literally re-grading the scan with the fixed findings removed,
// so "D (58) → A (96)" is the real computeGrade output, not an estimate.

import { computeGrade, findingPenalty, type Grade } from "./grade";
import {
  resolveRemediation,
  type DependencyGraph,
  type Remediation,
} from "./resolution";
import type { DependencyType, ScanResult, ScanVulnerability } from "./types";

export type RemediationKind =
  /** Known-malicious package — remove it, never upgrade it. */
  | "remove"
  /** Direct dependency with a fixed release — bump package.json. */
  | "upgrade"
  /** Transitive dependency with a fixed release — pin via npm `overrides`. */
  | "override";

export interface RemediationAction {
  kind: RemediationKind;
  package: string;
  installedVersion: string;
  /** The version to move to: the highest fixedVersion across this package's
   *  fixable findings, so one bump clears all of them. null for `remove`. */
  targetVersion: string | null;
  dependencyType: DependencyType;
  /** OSV ids this action resolves. */
  resolves: string[];
  /** Fixly Score points this action recovers (grade arithmetic, not a guess). */
  pointsRecovered: number;
  /** Copy-paste shell command that performs the action. */
  command: string;
  /** Why this action is ranked where it is. */
  reason: string;
  /** Structured resolution decision (path, semver distance, risk, rationale)
   *  from the resolution engine. Absent on `remove` actions — malware is
   *  removed, not resolved to a version. */
  resolution?: Remediation;
}

/** A finding the engine cannot fix automatically (no fixed release published). */
export interface UnfixableFinding {
  package: string;
  installedVersion: string;
  osvId: string;
  severity: ScanVulnerability["severity"];
}

export interface GradeForecast {
  before: { grade: Grade; score: number };
  /** The grade computeGrade would emit with every planned fix applied. */
  after: { grade: Grade; score: number };
  pointsRecovered: number;
}

export interface RemediationPlan {
  /** Malware removals first, then by points recovered, largest first. */
  actions: RemediationAction[];
  unfixable: UnfixableFinding[];
  /** Findings a published fix exists for, but a dependent's declared range
   *  forbids it (BLOCKED_BY_PARENT) — advice-only, no action offered. Only
   *  populated when a dependency graph was provided. */
  blocked: Remediation[];
  forecast: GradeForecast;
  totalFindings: number;
  fixableFindings: number;
}

export interface BuildRemediationPlanOptions {
  /** Lock-file dependency graph (lock-graph.ts). When provided, targets are
   *  checked against every dependent's declared range and blocked fixes move
   *  to `plan.blocked`. Without it, behavior matches the graph-less engine. */
  graph?: DependencyGraph | null;
}

/**
 * A malicious package must be REMOVED (not upgraded) when it is declared
 * directly — you can `npm uninstall` it — or when it has no published fix, so
 * there is nothing safe to move to. The one exception is a **transitive**
 * malicious package that DOES have a fixed release (e.g. fsevents <1.2.11): you
 * cannot uninstall a dependency you did not declare, so the only actionable,
 * safe remediation is to pin the whole tree to the fixed version via
 * `overrides`. Non-malicious findings are never "remove".
 */
function mustRemovePackage(vulns: ScanVulnerability[]): boolean {
  if (!vulns.some((v) => v.malicious)) return false;
  const isTransitive = vulns[0].dependencyType === "transitive";
  const hasUnfixedMalware = vulns.some((v) => v.malicious && v.fixedVersion === null);
  return !isTransitive || hasUnfixedMalware;
}

function buildRemoveAction(
  vulns: ScanVulnerability[],
  points: number
): RemediationAction {
  const first = vulns[0];
  return {
    kind: "remove",
    package: first.package,
    installedVersion: first.installedVersion,
    targetVersion: null,
    dependencyType: first.dependencyType,
    resolves: vulns.map((v) => v.osvId),
    pointsRecovered: points,
    command:
      first.dependencyType === "transitive"
        ? `npm ls ${first.package} # malicious transitive package — remove or replace the dependency that pulls it in`
        : `npm uninstall ${first.package}`,
    reason: `known MALICIOUS package — remove it, do not upgrade it`,
  };
}

function buildAction(
  vulns: ScanVulnerability[],
  points: number,
  resolution: Remediation
): RemediationAction {
  const first = vulns[0];
  const worst = vulns.reduce((a, b) => (findingPenalty(b) > findingPenalty(a) ? b : a));
  const resolves = vulns.map((v) => v.osvId);
  const n = resolves.length;

  // Callers only build upgrade/override actions for resolutions with a target.
  const targetVersion = resolution.targetVersion as string;

  const why = worst.malicious
    ? `${worst.cveId ?? worst.osvId} flags malicious code — pin past it to the fixed release`
    : worst.knownExploited
      ? `${worst.cveId ?? worst.osvId} is exploited in the wild (CISA KEV)`
      : worst.pocCount !== null && worst.pocCount > 0
        ? `${worst.cveId ?? worst.osvId} has public exploit PoCs`
        : `${worst.cveId ?? worst.osvId} (${worst.severity})`;
  const clears = n === 1 ? `clears 1 finding` : `clears ${n} findings`;

  if (first.dependencyType === "transitive") {
    return {
      kind: "override",
      package: first.package,
      installedVersion: first.installedVersion,
      targetVersion,
      dependencyType: first.dependencyType,
      resolves,
      pointsRecovered: points,
      command: `npm pkg set overrides.${first.package}=${targetVersion} && npm install`,
      reason: `${why} — transitive; pin via overrides, ${clears}`,
      resolution,
    };
  }
  return {
    kind: "upgrade",
    package: first.package,
    installedVersion: first.installedVersion,
    targetVersion,
    dependencyType: first.dependencyType,
    resolves,
    pointsRecovered: points,
    command: `npm install ${first.package}@${targetVersion}`,
    reason: `${why} — ${clears}`,
    resolution,
  };
}

/**
 * Build the remediation plan for a completed scan: one action per vulnerable
 * package@version (malware → remove, unless it's transitive with a published
 * fix → override; direct → upgrade; transitive → override), plus the Grade
 * Forecast for applying all of them. Deterministic.
 */
export function buildRemediationPlan(
  result: ScanResult,
  options: BuildRemediationPlanOptions = {}
): RemediationPlan {
  const graph = options.graph ?? null;
  const byPackage = new Map<string, ScanVulnerability[]>();
  for (const v of result.vulnerabilities) {
    const key = `${v.package}@${v.installedVersion}`;
    const list = byPackage.get(key);
    if (list) list.push(v);
    else byPackage.set(key, [v]);
  }

  const actions: RemediationAction[] = [];
  const unfixable: UnfixableFinding[] = [];
  const blocked: Remediation[] = [];
  const remaining: ScanVulnerability[] = [];

  for (const vulns of byPackage.values()) {
    const remove = mustRemovePackage(vulns);
    // Removal clears everything for the package; upgrades/overrides clear only
    // findings with a published fixed release (this includes a transitive
    // malware advisory that has a fix — pinned via overrides, not removed).
    const fixed = remove ? vulns : vulns.filter((v) => v.fixedVersion !== null);
    const leftover = remove ? [] : vulns.filter((v) => v.fixedVersion === null);

    if (remove) {
      const points = fixed.reduce((sum, v) => sum + findingPenalty(v), 0);
      actions.push(buildRemoveAction(fixed, Math.round(points * 10) / 10));
    } else if (fixed.length > 0) {
      const resolution = resolveRemediation(fixed, graph);
      if (resolution.path === "BLOCKED_BY_PARENT") {
        if (fixed.some((v) => v.malicious)) {
          // Malware must never sit in an advice-only bucket: when the safe
          // override is blocked by a parent's range, fall back to manual
          // removal of whatever pulls it in.
          const points = fixed.reduce((sum, v) => sum + findingPenalty(v), 0);
          actions.push(buildRemoveAction(fixed, Math.round(points * 10) / 10));
        } else {
          blocked.push(resolution);
          for (const v of fixed) remaining.push(v);
        }
      } else {
        const points = fixed.reduce((sum, v) => sum + findingPenalty(v), 0);
        actions.push(buildAction(fixed, Math.round(points * 10) / 10, resolution));
      }
    }
    for (const v of leftover) {
      remaining.push(v);
      unfixable.push({
        package: v.package,
        installedVersion: v.installedVersion,
        osvId: v.osvId,
        severity: v.severity,
      });
    }
  }

  // Malware removals always lead; everything else by recovered points.
  actions.sort((a, b) => {
    if ((a.kind === "remove") !== (b.kind === "remove")) {
      return a.kind === "remove" ? -1 : 1;
    }
    return b.pointsRecovered - a.pointsRecovered;
  });

  const before = computeGrade(result);
  const after = computeGrade({ ...result, vulnerabilities: remaining });

  const blockedCount = blocked.reduce((sum, b) => {
    // Blocked findings stay in `remaining` (the forecast never counts a fix we
    // don't offer); count them per package group for the fixable tally.
    return sum + (byPackage.get(`${b.package}@${b.installedVersion}`)?.filter((v) => v.fixedVersion !== null).length ?? 0);
  }, 0);

  return {
    actions,
    unfixable,
    blocked,
    forecast: {
      before: { grade: before.grade, score: before.score },
      after: { grade: after.grade, score: after.score },
      pointsRecovered: Math.round((after.score - before.score) * 10) / 10,
    },
    totalFindings: result.vulnerabilities.length,
    fixableFindings: result.vulnerabilities.length - unfixable.length - blockedCount,
  };
}

