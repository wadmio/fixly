import type { ScanResult } from "./types";

// Simple in-memory, per-process scan cache for development/demo: repeated scans
// of the same repo within the TTL return the previous result instead of hitting
// GitHub/OSV again. It is NOT a persistent store — it resets on restart and is
// not shared across server instances. Only successful scans are cached.

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
