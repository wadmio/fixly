// Scan-over-scan comparison — pure functions with no Node/network deps, safe
// to import in client components (exported at @fixly/core/compare).
//
// A finding's identity is (package, advisory id): if the same advisory still
// applies to the same package on the next scan it is "unchanged" even when the
// installed version moved (e.g. bumped but still inside the affected range);
// when it disappears it was "resolved"; new pairs are "added".

import type { ScanVulnerability, Severity } from "./types";

/** Stable identity for a finding across scans. */
export function findingKey(v: Pick<ScanVulnerability, "package" | "osvId">): string {
  return `${v.package}::${v.osvId}`;
}

export interface ScanDelta {
  /** Finding keys present now but not in the previous scan. */
  added: string[];
  /** Finding keys present in the previous scan but no longer reported. */
  resolved: string[];
  /** Finding keys present in both scans. */
  unchanged: string[];
}

/**
 * Diff two scans by their finding keys. Order of the inputs is preserved in
 * the output lists.
 */
export function compareFindingKeys(previous: string[], next: string[]): ScanDelta {
  const prevSet = new Set(previous);
  const nextSet = new Set(next);
  return {
    added: next.filter((k) => !prevSet.has(k)),
    resolved: previous.filter((k) => !nextSet.has(k)),
    unchanged: next.filter((k) => prevSet.has(k)),
  };
}

/** Per-finding metadata that can change without the key changing. */
export interface FindingSnapshotEntry {
  knownExploited: boolean;
}

/** findingKey → metadata; what a real-time watcher remembers between scans. */
export type FindingSnapshot = Record<string, FindingSnapshotEntry>;

export function snapshotFindings(
  vulnerabilities: Array<Pick<ScanVulnerability, "package" | "osvId" | "knownExploited">>
): FindingSnapshot {
  const snapshot: FindingSnapshot = {};
  for (const v of vulnerabilities) {
    snapshot[findingKey(v)] = { knownExploited: v.knownExploited };
  }
  return snapshot;
}

export interface FindingSnapshotDiff<V> {
  /** Findings whose key was absent from the previous snapshot. */
  added: V[];
  /** Carried-over findings whose knownExploited flipped false → true —
   *  same key, new urgency (a KEV catalog addition). */
  escalated: V[];
  /** Keys present before and gone now. */
  resolvedKeys: string[];
}

/**
 * Diff a scan's findings against a previous snapshot, distinguishing brand-new
 * findings from KEV escalations of carried-over ones. Powers the real-time
 * surfaces (CLI daemon, extension guardian).
 */
export function diffFindingSnapshot<
  V extends Pick<ScanVulnerability, "package" | "osvId" | "knownExploited">,
>(previous: FindingSnapshot, vulnerabilities: V[]): FindingSnapshotDiff<V> {
  const added: V[] = [];
  const escalated: V[] = [];
  const currentKeys = new Set<string>();
  for (const v of vulnerabilities) {
    const key = findingKey(v);
    currentKeys.add(key);
    const before = previous[key];
    if (!before) added.push(v);
    else if (!before.knownExploited && v.knownExploited) escalated.push(v);
  }
  const resolvedKeys = Object.keys(previous).filter((k) => !currentKeys.has(k));
  return { added, escalated, resolvedKeys };
}

/** Compact per-severity totals, suitable for storage and trend displays. */
export type SeverityCounts = Record<Severity, number>;

export function countBySeverity(
  vulnerabilities: Array<Pick<ScanVulnerability, "severity">>
): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of vulnerabilities) counts[v.severity]++;
  return counts;
}
