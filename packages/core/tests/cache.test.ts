import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  getCachedScan,
  setCachedScan,
  clearScanCache,
  scanCacheKey,
} from "../src/cache";
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
    directPackages: 0,
    transitivePackages: 0,
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

describe("scanCacheKey", () => {
  it("treats protocol/host variants of the same repo as one key", () => {
    expect(scanCacheKey("https://github.com/o/r")).toBe(
      scanCacheKey("github.com/o/r")
    );
  });

  it("does not collide across different repo / branch / subpath inputs", () => {
    const keys = [
      scanCacheKey("https://github.com/o/r"),
      scanCacheKey("https://github.com/o/r2"),
      scanCacheKey("https://github.com/o2/r"),
      scanCacheKey("https://github.com/o/r/tree/main"),
      scanCacheKey("https://github.com/o/r/tree/dev"),
      scanCacheKey("https://github.com/o/r/tree/main/pkg-a"),
      scanCacheKey("https://github.com/o/r/tree/main/pkg-b"),
    ];
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("includes branch + subpath so a subpath scan can't reuse a root-repo scan", () => {
    expect(scanCacheKey("https://github.com/o/r")).not.toBe(
      scanCacheKey("https://github.com/o/r/tree/main/packages/web")
    );
  });
});
