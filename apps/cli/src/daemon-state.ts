// Daemon state — what the daemon remembers between scans (and between runs):
// per-project finding snapshots that turn "a scan" into "what changed".
// Persisted at ~/.fixly/daemon-state.json (FIXLY_HOME overrides the directory;
// tests point it at a temp dir), so a daemon restarted after downtime diffs
// against what it last saw — advisories published while it was off still
// surface as events. The diffing logic is pure and separated from fs so it
// can be unit-tested directly.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  computeGrade,
  findingKey,
  type Grade,
  type ScanResult,
  type ScanVulnerability,
  type Severity,
} from "@fixly/core";

export interface FindingSnapshot {
  severity: Severity;
  knownExploited: boolean;
}

export interface ProjectSnapshot {
  lastScanAt: string;
  grade: { grade: Grade; score: number };
  /** findingKey (package::osvId) → metadata that can escalate without the
   *  key changing (KEV additions). */
  findings: Record<string, FindingSnapshot>;
}

export interface DaemonState {
  version: 1;
  projects: Record<string, ProjectSnapshot>;
}

export function snapshotFromScan(result: ScanResult): ProjectSnapshot {
  const grade = computeGrade(result);
  const findings: Record<string, FindingSnapshot> = {};
  for (const v of result.vulnerabilities) {
    findings[findingKey(v)] = {
      severity: v.severity,
      knownExploited: v.knownExploited,
    };
  }
  return {
    lastScanAt: result.scannedAt,
    grade: { grade: grade.grade, score: grade.score },
    findings,
  };
}

export interface ScanDiff {
  /** Findings whose key was absent from the previous snapshot. */
  added: ScanVulnerability[];
  /** Carried-over findings whose knownExploited flipped false → true —
   *  same key, new urgency (a KEV catalog addition). */
  escalated: ScanVulnerability[];
  /** Keys present before and gone now. */
  resolvedKeys: string[];
}

export function diffAgainstSnapshot(
  prev: ProjectSnapshot,
  result: ScanResult
): ScanDiff {
  const added: ScanVulnerability[] = [];
  const escalated: ScanVulnerability[] = [];
  const currentKeys = new Set<string>();
  for (const v of result.vulnerabilities) {
    const key = findingKey(v);
    currentKeys.add(key);
    const before = prev.findings[key];
    if (!before) added.push(v);
    else if (!before.knownExploited && v.knownExploited) escalated.push(v);
  }
  const resolvedKeys = Object.keys(prev.findings).filter((k) => !currentKeys.has(k));
  return { added, escalated, resolvedKeys };
}

export function fixlyHome(): string {
  return process.env.FIXLY_HOME ?? join(homedir(), ".fixly");
}

function stateFilePath(): string {
  return join(fixlyHome(), "daemon-state.json");
}

/** Missing or corrupt state is a first run, never an error. */
export async function loadState(): Promise<DaemonState> {
  try {
    const parsed = JSON.parse(await readFile(stateFilePath(), "utf8")) as DaemonState;
    if (parsed && parsed.version === 1 && parsed.projects && typeof parsed.projects === "object") {
      return parsed;
    }
  } catch {
    // fall through to a fresh state
  }
  return { version: 1, projects: {} };
}

/** Atomic write (temp file + rename) so a crash mid-write can't corrupt state. */
export async function saveState(state: DaemonState): Promise<void> {
  const path = stateFilePath();
  await mkdir(fixlyHome(), { recursive: true });
  const tmp = `${path}.tmp`;
  await writeFile(tmp, JSON.stringify(state, null, 2) + "\n", "utf8");
  await rename(tmp, path);
}
