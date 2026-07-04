// Scan history unit tests — node env with a stubbed localStorage (full DOM
// rendering under Vitest is broken in this toolchain; see CLAUDE.md).
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  loadHistory,
  recordScan,
  clearHistory,
  type ScanHistoryEntry,
} from "../lib/history";

function stubLocalStorage(): void {
  const store = new Map<string, string>();
  vi.stubGlobal("window", {
    localStorage: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    },
  });
}

function entry(over: Partial<ScanHistoryEntry>): ScanHistoryEntry {
  return {
    repo: "owner/repo",
    url: "/dashboard/results?repo=x",
    scannedAt: "2026-07-01T00:00:00Z",
    totalPackages: 10,
    directPackages: 4,
    transitivePackages: 6,
    totalFindings: 2,
    counts: { critical: 1, high: 1, medium: 0, low: 0, unknown: 0 },
    findingKeys: ["lodash::GHSA-1", "axios::GHSA-2"],
    ...over,
  };
}

describe("scan history", () => {
  beforeEach(() => {
    stubLocalStorage();
    clearHistory();
  });

  it("records a first scan with no delta", () => {
    const { previous, delta } = recordScan(entry({}));
    expect(previous).toBeNull();
    expect(delta).toBeNull();
    expect(loadHistory()).toHaveLength(1);
  });

  it("computes added/resolved against the previous scan of the same repo", () => {
    recordScan(entry({}));
    const { delta } = recordScan(
      entry({
        scannedAt: "2026-07-02T00:00:00Z",
        findingKeys: ["axios::GHSA-2", "ejs::GHSA-3"],
      })
    );
    expect(delta).toEqual({
      added: ["ejs::GHSA-3"],
      resolved: ["lodash::GHSA-1"],
      unchanged: ["axios::GHSA-2"],
    });
    expect(loadHistory()).toHaveLength(2);
  });

  it("is idempotent for the same (repo, scannedAt)", () => {
    recordScan(entry({}));
    recordScan(entry({}));
    expect(loadHistory()).toHaveLength(1);
  });

  it("does not diff against a different repo's scans", () => {
    recordScan(entry({ repo: "someone/else" }));
    const { previous } = recordScan(entry({}));
    expect(previous).toBeNull();
  });

  it("survives corrupted storage", () => {
    window.localStorage.setItem("fixly.scan-history.v1", "{not json");
    expect(loadHistory()).toEqual([]);
  });
});
