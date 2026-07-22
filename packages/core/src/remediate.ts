// Fixly Remediation Engine — turns a completed scan into an ordered, executable
// fix plan plus a Grade Forecast: the exact Fixly Score the project would earn
// if the plan were applied. Pure functions over a ScanResult (no network, no
// fs), so every surface — CLI `fixly fix`, the web report, the VS Code panel —
// shows the same plan for the same scan.
//
// Same philosophy as the grade: earned arithmetic, not vibes. The forecast is
// computed by literally re-grading the scan with the fixed findings removed,
// so "D (58) → A (96)" is the real computeGrade output, not an estimate.

import { computeGrade, findingPenalty, type Grade } from "./grade";
import { compareSemver } from "./matching";
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
  forecast: GradeForecast;
  totalFindings: number;
  fixableFindings: number;
}

/** Highest of two semver strings; falls back to `b` when incomparable. */
function maxVersion(a: string | null, b: string): string {
  if (a === null) return b;
  const cmp = compareSemver(a, b);
  return cmp !== null && cmp >= 0 ? a : b;
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

function buildAction(
  vulns: ScanVulnerability[],
  points: number
): RemediationAction {
  const first = vulns[0];
  const worst = vulns.reduce((a, b) => (findingPenalty(b) > findingPenalty(a) ? b : a));
  const resolves = vulns.map((v) => v.osvId);
  const n = resolves.length;

  if (mustRemovePackage(vulns)) {
    return {
      kind: "remove",
      package: first.package,
      installedVersion: first.installedVersion,
      targetVersion: null,
      dependencyType: first.dependencyType,
      resolves,
      pointsRecovered: points,
      command:
        first.dependencyType === "transitive"
          ? `npm ls ${first.package} # malicious transitive package — remove or replace the dependency that pulls it in`
          : `npm uninstall ${first.package}`,
      reason: `known MALICIOUS package — remove it, do not upgrade it`,
    };
  }

  let target: string | null = null;
  for (const v of vulns) {
    if (v.fixedVersion) target = maxVersion(target, v.fixedVersion);
  }
  // Callers only build upgrade/override actions for packages with a fix.
  const targetVersion = target as string;

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
  };
}

/**
 * Build the remediation plan for a completed scan: one action per vulnerable
 * package@version (malware → remove, unless it's transitive with a published
 * fix → override; direct → upgrade; transitive → override), plus the Grade
 * Forecast for applying all of them. Deterministic.
 */
export function buildRemediationPlan(result: ScanResult): RemediationPlan {
  const byPackage = new Map<string, ScanVulnerability[]>();
  for (const v of result.vulnerabilities) {
    const key = `${v.package}@${v.installedVersion}`;
    const list = byPackage.get(key);
    if (list) list.push(v);
    else byPackage.set(key, [v]);
  }

  const actions: RemediationAction[] = [];
  const unfixable: UnfixableFinding[] = [];
  const remaining: ScanVulnerability[] = [];

  for (const vulns of byPackage.values()) {
    const remove = mustRemovePackage(vulns);
    // Removal clears everything for the package; upgrades/overrides clear only
    // findings with a published fixed release (this includes a transitive
    // malware advisory that has a fix — pinned via overrides, not removed).
    const fixed = remove ? vulns : vulns.filter((v) => v.fixedVersion !== null);
    const leftover = remove ? [] : vulns.filter((v) => v.fixedVersion === null);

    if (fixed.length > 0) {
      const points = fixed.reduce((sum, v) => sum + findingPenalty(v), 0);
      actions.push(buildAction(fixed, Math.round(points * 10) / 10));
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

  return {
    actions,
    unfixable,
    forecast: {
      before: { grade: before.grade, score: before.score },
      after: { grade: after.grade, score: after.score },
      pointsRecovered: Math.round((after.score - before.score) * 10) / 10,
    },
    totalFindings: result.vulnerabilities.length,
    fixableFindings: result.vulnerabilities.length - unfixable.length,
  };
}

export interface AppliedRemediation {
  /** The rewritten package.json text (original formatting-adjacent: detected
   *  indentation, trailing newline preserved). */
  text: string;
  /** Human-readable descriptions of each edit, in plan order. */
  changes: string[];
  /** Actions that could not be applied to this manifest (e.g. an `upgrade`
   *  whose package is not declared in it). Their commands still work by hand. */
  skipped: RemediationAction[];
}

/** Keep the caller's range style: `^1.2.3` stays caret, `~` stays tilde,
 *  exact stays exact; anything else (ranges, tags) becomes a caret pin. */
function rewriteRange(oldRange: string, target: string): string {
  if (oldRange.startsWith("^")) return `^${target}`;
  if (oldRange.startsWith("~")) return `~${target}`;
  if (/^\d/.test(oldRange)) return target;
  return `^${target}`;
}

/**
 * Apply a remediation plan to package.json text: bump direct dependencies to
 * their fixed versions (preserving `^`/`~` style), add `overrides` entries for
 * transitive pins, and delete malicious direct dependencies. Pure — returns
 * the new text; the caller decides whether to write it and must run the
 * package manager afterwards to realize the change.
 */
export function applyRemediationPlan(
  packageJsonText: string,
  plan: RemediationPlan
): AppliedRemediation {
  const manifest = JSON.parse(packageJsonText) as Record<string, unknown>;
  const deps = (manifest.dependencies ?? null) as Record<string, string> | null;
  const devDeps = (manifest.devDependencies ?? null) as Record<string, string> | null;
  const changes: string[] = [];
  const skipped: RemediationAction[] = [];

  for (const action of plan.actions) {
    const inDeps = deps && action.package in deps ? deps : null;
    const inDevDeps = devDeps && action.package in devDeps ? devDeps : null;

    if (action.kind === "remove") {
      if (!inDeps && !inDevDeps) {
        skipped.push(action);
        continue;
      }
      if (inDeps) delete inDeps[action.package];
      if (inDevDeps) delete inDevDeps[action.package];
      changes.push(`removed ${action.package} (malicious)`);
      continue;
    }

    if (action.kind === "upgrade") {
      const section = inDeps ?? inDevDeps;
      if (!section || !action.targetVersion) {
        skipped.push(action);
        continue;
      }
      const oldRange = section[action.package];
      const newRange = rewriteRange(oldRange, action.targetVersion);
      section[action.package] = newRange;
      changes.push(`${action.package}: "${oldRange}" → "${newRange}"`);
      continue;
    }

    // override — pin the transitive dependency for the whole tree.
    if (!action.targetVersion) {
      skipped.push(action);
      continue;
    }
    const overrides = (manifest.overrides ?? {}) as Record<string, unknown>;
    overrides[action.package] = action.targetVersion;
    manifest.overrides = overrides;
    changes.push(`overrides.${action.package} = "${action.targetVersion}" (transitive pin)`);
  }

  const indent = /\n([ \t]+)"/.exec(packageJsonText)?.[1] ?? "  ";
  const trailingNewline = packageJsonText.endsWith("\n") ? "\n" : "";
  return {
    text: JSON.stringify(manifest, null, indent) + trailingNewline,
    changes,
    skipped,
  };
}
