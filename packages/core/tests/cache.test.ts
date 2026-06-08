import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { getCachedScan, setCachedScan, clearScanCache } from "../src/cache";
import type { ScanResult } from "../src/types";

function fakeResult(repo: string): ScanResult {
  return {
    repo,
    target: {
      owner: null,
      repo: null,
      branch: null,
      subpath: null,
      filesFound: [],
      filesMissing: [],
    },
    scannedAt: "2026-01-01T00:00:00Z",
    source: "osv",
    dependencies: [],
    totalPackages: 0,
    resolvedPackages: 0,
    vulnerabilities: [],
    warnings: [],
  };
}

beforeEach(() => clearScanCache());
afterEach(() => vi.useRealTimers());

describe("scan cache", () => {
  it("returns a stored value within the TTL", () => {
    setCachedScan("k", fakeResult("k"), 1000);
    expect(getCachedScan("k")?.repo).toBe("k");
  });

  it("expires entries after the TTL", () => {
    vi.useFakeTimers();
    setCachedScan("k", fakeResult("k"), 1000);
    vi.advanceTimersByTime(1001);
    expect(getCachedScan("k")).toBeNull();
  });

  it("clears all entries", () => {
    setCachedScan("k", fakeResult("k"), 10_000);
    clearScanCache();
    expect(getCachedScan("k")).toBeNull();
  });

  it("misses unknown keys", () => {
    expect(getCachedScan("nope")).toBeNull();
  });
});
