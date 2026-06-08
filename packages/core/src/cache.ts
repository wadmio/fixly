import type { ScanResult } from "./types";
import { parseGitHubUrl } from "./github-url";

// Simple in-memory, per-process scan cache for development/demo: repeated scans
// of the same repo within the TTL return the previous result instead of hitting
// GitHub/OSV again. It is NOT a persistent store — it resets on restart and is
// not shared across server instances. Only successful scans are cached.

/**
 * Build a cache key from every input that affects a scan result: owner, repo,
 * branch, and subpath. Equivalent URLs (protocol/trailing-slash variants)
 * collapse to one key; different repo/branch/subpath never collide. Unparseable
 * URLs fall back to the trimmed raw string (those produce errors and aren't
 * cached, but keep keys distinct regardless).
 */
export function scanCacheKey(repoUrl: string): string {
  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) return `raw:${repoUrl.trim()}`;
  return `gh:${parsed.owner}/${parsed.repo}@${parsed.branch ?? ""}#${parsed.subpath ?? ""}`;
}

interface CacheEntry {
  value: ScanResult;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes
const store = new Map<string, CacheEntry>();

export function getCachedScan(key: string): ScanResult | null {
  const entry = store.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    store.delete(key);
    return null;
  }
  return entry.value;
}

export function setCachedScan(
  key: string,
  value: ScanResult,
  ttlMs: number = DEFAULT_TTL_MS
): void {
  store.set(key, { value, expiresAt: Date.now() + ttlMs });
}

/** Clear the in-memory scan cache (used by tests and tooling). */
export function clearScanCache(): void {
  store.clear();
}
