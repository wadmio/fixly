// Fixly Resolution Engine — decides HOW a vulnerable package can be fixed and
// explains WHY, as data. Pure functions over normalized findings plus (when
// available) the lock-file dependency graph: no network, no fs, so every
// decision is unit-testable without a live scan.
//
// The engine's honesty constraints:
//   - Candidate versions come only from OSV fixed events (we cannot enumerate
//     the npm registry here). If the minimal fix violates a dependent's range
//     we report BLOCKED_BY_PARENT rather than probing versions we can't see.
//   - Unparseable dependent ranges are "unknown" — noted in the rationale,
//     never counted as blockers.
//   - NO_FIX_AVAILABLE and BLOCKED_BY_PARENT are legitimate terminal states,
//     not errors; neither produces an editable action.

import { compareSemver, parseVersion, satisfiesRange } from "./matching";
import type { ScanVulnerability } from "./types";

/** How a finding can be resolved. */
export type ResolutionPath =
  /** Direct dependency — edit its range in package.json. */
  | "DIRECT"
  /** Transitive dependency — needs an npm `overrides` entry (elevated risk:
   *  the parent was never necessarily tested against the forced version). */
  | "TRANSITIVE_OVERRIDE"
  /** A fixed release exists but a dependent's declared range forbids it —
   *  advice-only, no edit offered. */
  | "BLOCKED_BY_PARENT"
  /** No fixed release published for any of the findings. */
  | "NO_FIX_AVAILABLE";

export type SemverDistance = "PATCH" | "MINOR" | "MAJOR";

/** Drives the UI: elevated remediations must be visually distinct. */
export type RemediationRisk = "low" | "elevated";

/** A package that declares a range on the vulnerable package. */
export interface DependentEdge {
  /** "name@version" of the dependent, or "(root)" for the workspace manifest. */
  dependent: string;
  /** The range the dependent declares (e.g. "^1.2.0"). */
  range: string;
}

/** The graph view the engine needs — implemented by lock-graph.ts over a
 *  v2/v3 package-lock.json; fakeable in tests. */
export interface DependencyGraph {
  dependentsOf(name: string, version: string): DependentEdge[];
}

/** Structured remediation decision for one vulnerable package@version. */
export interface Remediation {
  package: string;
  installedVersion: string;
  path: ResolutionPath;
  /** The minimum version clearing every fixable finding that also satisfies
   *  the checked dependent constraints. null for terminal paths. */
  targetVersion: string | null;
  /** Jump size from installed to target; null when either side is
   *  unparseable or there is no target. */
  semverDistance: SemverDistance | null;
  /** null for terminal paths (no action is offered, so nothing to risk-rate). */
  risk: RemediationRisk | null;
  /** Plain-English explanation of the choice (or of why there is no choice). */
  rationale: string;
  /** Dependents whose declared range definitely excludes the fix candidate.
   *  Non-empty only for BLOCKED_BY_PARENT. */
  blockers: DependentEdge[];
  /** OSV ids this remediation clears. Empty for terminal paths. */
  resolves: string[];
  /** False when no dependency graph was available (v1/absent lock file), so
   *  dependent constraints could not be checked. */
  constraintsChecked: boolean;
}

/** Highest of two semver strings; falls back to `b` when incomparable. */
function maxVersion(a: string | null, b: string): string {
  if (a === null) return b;
  const cmp = compareSemver(a, b);
  return cmp !== null && cmp >= 0 ? a : b;
}

/** Classify the jump from `from` to `to`: which part changes first. */
export function semverDistanceBetween(from: string, to: string): SemverDistance | null {
  const a = parseVersion(from);
  const b = parseVersion(to);
  if (!a || !b) return null;
  if ((a.parts[0] ?? 0) !== (b.parts[0] ?? 0)) return "MAJOR";
  if ((a.parts[1] ?? 0) !== (b.parts[1] ?? 0)) return "MINOR";
  return "PATCH";
}

function describeDistance(distance: SemverDistance | null): string {
  if (distance === null) return "jump size could not be determined";
  return `${distance.toLowerCase()}-level bump`;
}

/**
 * Resolve the remediation for all findings of one package@version.
 *
 * `findings` must be non-empty and share `package`/`installedVersion`.
 * `graph` is the lock-file dependency graph, or null when unavailable —
 * dependent-constraint checks are then skipped and the rationale says so.
 *
 * Malware removal is intentionally NOT decided here: a malicious package is
 * removed, not moved to a version (remediate.ts owns that call). The one
 * malware case that flows through here is the transitive-with-published-fix
 * override, which resolves like any transitive finding.
 */
export function resolveRemediation(
  findings: ScanVulnerability[],
  graph: DependencyGraph | null = null
): Remediation {
  const first = findings[0];
  const base = {
    package: first.package,
    installedVersion: first.installedVersion,
    blockers: [] as DependentEdge[],
    constraintsChecked: false,
  };
  const isTransitive = first.dependencyType === "transitive";

  const fixable = findings.filter((f) => f.fixedVersion !== null);
  if (fixable.length === 0) {
    const ids = findings.map((f) => f.osvId).join(", ");
    return {
      ...base,
      path: "NO_FIX_AVAILABLE",
      targetVersion: null,
      semverDistance: null,
      risk: null,
      rationale: `no fixed release has been published for ${ids} — nothing safe to move to yet; re-scan later or consider replacing the package`,
      resolves: [],
    };
  }

  // The minimum version clearing EVERY fixable finding: each finding's
  // fixedVersion is already the smallest fix above the installed version
  // (normalize.ts), so the smallest version clearing all of them is the max.
  let target: string | null = null;
  for (const f of fixable) target = maxVersion(target, f.fixedVersion as string);
  const targetVersion = target as string;

  const notes: string[] = [];
  // Sanity-check the candidate against each finding's affected ranges (they
  // are ">=X <Y"-style comparator strings, evaluable with satisfiesRange).
  const residual = fixable.filter((f) =>
    f.affectedRanges.some((r) => satisfiesRange(targetVersion, r) === true)
  );
  if (residual.length > 0) {
    notes.push(
      `note: ${residual.map((f) => f.osvId).join(", ")} may still affect ${targetVersion} (another affected range covers it)`
    );
  }

  // Dependent-constraint check (needs the lock graph).
  let constraintsChecked = false;
  const blockers: DependentEdge[] = [];
  const unknownRanges: DependentEdge[] = [];
  if (graph) {
    constraintsChecked = true;
    for (const edge of graph.dependentsOf(first.package, first.installedVersion)) {
      // The root manifest's own range is exactly what a DIRECT fix rewrites —
      // it can never block.
      if (edge.dependent === "(root)") continue;
      const ok = satisfiesRange(targetVersion, edge.range);
      if (ok === false) blockers.push(edge);
      else if (ok === null) unknownRanges.push(edge);
    }
  }

  const n = fixable.length;
  const clears = `clears ${n} ${n === 1 ? "advisory" : "advisories"} (${fixable
    .map((f) => f.osvId)
    .join(", ")})`;

  if (blockers.length > 0) {
    const who = blockers
      .map((b) => `${b.dependent} requires "${b.range}"`)
      .join("; ");
    return {
      ...base,
      path: "BLOCKED_BY_PARENT",
      targetVersion: null,
      semverDistance: null,
      risk: null,
      rationale: `a fixed release exists (${targetVersion}) but ${who}, which excludes it — forcing it would create a combination the ${blockers.length === 1 ? "parent" : "parents"} never tested. No edit offered; this unblocks when the ${blockers.length === 1 ? "parent updates its" : "parents update their"} range`,
      blockers,
      resolves: [],
      constraintsChecked,
    };
  }

  if (unknownRanges.length > 0) {
    notes.push(
      `could not evaluate the range${unknownRanges.length === 1 ? "" : "s"} declared by ${unknownRanges
        .map((u) => u.dependent)
        .join(", ")} — treated as compatible, not as blocking`
    );
  }
  if (constraintsChecked) {
    notes.push("dependent ranges checked against the lock-file graph");
  } else {
    notes.push(
      "dependent ranges not checked (no v2/v3 package-lock.json graph available)"
    );
  }

  const distance = semverDistanceBetween(first.installedVersion, targetVersion);
  const resolves = fixable.map((f) => f.osvId);

  if (isTransitive) {
    return {
      ...base,
      path: "TRANSITIVE_OVERRIDE",
      targetVersion,
      semverDistance: distance,
      risk: "elevated",
      rationale: `${targetVersion} is the smallest release that ${clears}; ${first.package} is not declared in package.json, so the fix must be forced tree-wide via npm overrides — ${describeDistance(distance)} the dependents were not necessarily tested against. ${notes.join("; ")}`,
      blockers,
      resolves,
      constraintsChecked,
    };
  }

  const risk: RemediationRisk =
    distance === "MAJOR" || distance === null ? "elevated" : "low";
  return {
    ...base,
    path: "DIRECT",
    targetVersion,
    semverDistance: distance,
    risk,
    rationale: `upgrade to ${targetVersion} — the smallest release that ${clears}; ${describeDistance(distance)} from ${first.installedVersion}${distance === "MAJOR" ? " (may contain breaking changes — review the changelog)" : ""}. ${notes.join("; ")}`,
    blockers,
    resolves,
    constraintsChecked,
  };
}
