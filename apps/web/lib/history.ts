// Client-side scan history — localStorage-backed, so it works without any
// backend/database (deliberate: the capstone has no persistence layer).
// Each entry is a compact scan summary plus the finding keys needed to diff
// two scans of the same repository (@fixly/core/compare).

import { compareFindingKeys, type ScanDelta, type SeverityCounts } from "@fixly/core/compare";

export interface ScanHistoryEntry {
  /** Normalized display label (owner/repo, fixture label, or folder name). */
  repo: string;
  /** Link that re-runs this scan (results page URL with query). */
  url: string;
  scannedAt: string;
  totalPackages: number;
  directPackages: number;
  transitivePackages: number;
  totalFindings: number;
  counts: SeverityCounts;
  /** Stable finding identities for scan-over-scan comparison. */
  findingKeys: string[];
}

const STORAGE_KEY = "fixly.scan-history.v1";
const MAX_ENTRIES = 50;

function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

// ---------------------------------------------------------------------------
// External-store contract (for React useSyncExternalStore): a cached snapshot
// that stays referentially stable between writes, plus change notifications.
// ---------------------------------------------------------------------------
const EMPTY_HISTORY: ScanHistoryEntry[] = [];
let snapshot: ScanHistoryEntry[] | null = null;
const listeners = new Set<() => void>();

function notify(): void {
  snapshot = null; // invalidate — next getHistorySnapshot re-reads storage
  for (const listener of listeners) listener();
}

export function subscribeHistory(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Client snapshot — referentially stable until the next write. */
export function getHistorySnapshot(): ScanHistoryEntry[] {
  if (snapshot === null) snapshot = loadHistory();
  return snapshot;
}

/** Server/hydration snapshot — history is browser-only. */
export function getServerHistorySnapshot(): ScanHistoryEntry[] {
  return EMPTY_HISTORY;
}

export function loadHistory(): ScanHistoryEntry[] {
  if (!isBrowser()) return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? (parsed as ScanHistoryEntry[]) : [];
  } catch {
    // Corrupted storage — treat as empty rather than breaking the page.
    return [];
  }
}

function save(entries: ScanHistoryEntry[]): void {
  if (!isBrowser()) return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(entries.slice(0, MAX_ENTRIES)));
  } catch {
    // Quota exceeded / private mode — history is best-effort.
  }
  notify();
}

export function clearHistory(): void {
  if (!isBrowser()) return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
  notify();
}

export interface RecordOutcome {
  /** The most recent prior scan of the same repo, if any. */
  previous: ScanHistoryEntry | null;
  /** Diff vs that prior scan (null on a first scan). */
  delta: ScanDelta | null;
}

/**
 * Record a completed scan and return the delta against the previous scan of
 * the same repository. Idempotent for the same (repo, scannedAt) pair, so
 * React strict-mode double effects and page revisits don't duplicate entries.
 */
export function recordScan(entry: ScanHistoryEntry): RecordOutcome {
  const history = loadHistory();

  const existing = history.find(
    (e) => e.repo === entry.repo && e.scannedAt === entry.scannedAt
  );
  const previous =
    history.find(
      (e) => e.repo === entry.repo && e.scannedAt !== entry.scannedAt
    ) ?? null;

  const delta = previous
    ? compareFindingKeys(previous.findingKeys, entry.findingKeys)
    : null;

  if (!existing) {
    save([entry, ...history]);
  }

  return { previous, delta };
}
