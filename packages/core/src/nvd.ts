// NVD cross-referencing — second-source verification for findings with CVEs.
//
// OSV is the primary detection source (it matches npm package versions against
// affected ranges). NVD does not index npm packages directly, so it cannot
// *find* vulnerabilities for us — but it publishes an independent CVSS
// assessment per CVE. Cross-referencing lets the report say "this finding is
// confirmed by both OSV and NVD" and surface NVD's score alongside OSV's,
// which is exactly the multi-source transparency the report promises.
//
// NVD's public API is heavily rate-limited (5 requests / 30s without a key,
// 50 with one — https://nvd.nist.gov/developers/start-here). Enrichment is
// therefore best-effort by design: capped request count, per-request timeout,
// an overall time budget, and an in-memory CVE cache so repeated scans (demos,
// rescans) don't re-pay the cost. It never fails a scan — on any problem the
// findings simply stay OSV-only and a warning explains the coverage.

import { fetchWithRetry, mapWithConcurrency } from "./http";
import { BoundedMap } from "./bounded-map";
import type { NvdData, ScanVulnerability, Severity } from "./types";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/** Max CVEs fetched per scan, respecting NVD's public rate windows
 *  (5 requests / 30s without a key, 50 with one). */
const MAX_CVES_WITHOUT_KEY = 5;
const MAX_CVES_WITH_KEY = 40;
/** Per-request timeout — a slow NVD must never stall the scan. */
const REQUEST_TIMEOUT_MS = 4_000;
/** Overall enrichment budget per scan. Larger with a key: NVD is slow (~1-2s
 *  per request) and serial fetching under the 8s budget only cleared ~3 CVEs,
 *  so a key's higher cap was never reached. With a key we spend longer and
 *  fetch concurrently to actually approach the 40-CVE cap. */
const TIME_BUDGET_WITHOUT_KEY_MS = 8_000;
const TIME_BUDGET_WITH_KEY_MS = 15_000;
/** Concurrent NVD requests. Serial without a key (the 5/30s public window
 *  punishes bursts); a key's 50/30s window affords real parallelism. */
const CONCURRENCY_WITHOUT_KEY = 1;
const CONCURRENCY_WITH_KEY = 8;

// CVE → NvdData (or null when NVD had no usable CVSS data for it). Module-level
// so rescans and demo repeats hit the cache instead of the rate limit. Capped
// so a long-lived server can't accumulate CVE entries without bound.
const nvdCache = new BoundedMap<string, NvdData | null>(5000);

/** Test hook / manual reset. */
export function clearNvdCache(): void {
  nvdCache.clear();
}

const NVD_SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

interface NvdCveResponse {
  vulnerabilities?: Array<{
    cve?: {
      metrics?: {
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string } }>;
        cvssMetricV30?: Array<{ cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string } }>;
      };
    };
  }>;
}

function parseNvdResponse(body: NvdCveResponse): NvdData | null {
  const metrics = body.vulnerabilities?.[0]?.cve?.metrics;
  const cvss = metrics?.cvssMetricV31?.[0]?.cvssData ?? metrics?.cvssMetricV30?.[0]?.cvssData;
  if (!cvss) return null;
  return {
    cvssScore: typeof cvss.baseScore === "number" ? cvss.baseScore : null,
    cvssVector: cvss.vectorString ?? null,
    severity: cvss.baseSeverity ? NVD_SEVERITY_MAP[cvss.baseSeverity.toUpperCase()] ?? null : null,
  };
}

async function fetchNvdCve(
  cveId: string,
  apiKey: string | undefined,
  timeoutMs: number
): Promise<NvdData | null> {
  const cached = nvdCache.get(cveId);
  if (cached !== undefined) return cached;

  const res = await fetchWithRetry(
    `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`,
    { headers: apiKey ? { apiKey } : undefined },
    // No retry: retrying a timed-out NVD request would just burn the scan's
    // time budget (a fresh timeout per attempt can't help a slow endpoint).
    // Better to record the miss and move to the next CVE. timeoutMs is bounded
    // by the remaining budget so a single request can't overrun it.
    { retries: 0, timeoutMs }
  );
  if (!res.ok) throw new Error(`NVD ${res.status}`);

  const data = parseNvdResponse((await res.json()) as NvdCveResponse);
  nvdCache.set(cveId, data);
  return data;
}

export interface NvdEnrichmentOptions {
  /** Overrides the NVD_API_KEY environment variable. */
  apiKey?: string;
  /** Overall time budget in ms (default: 8000 without a key, 15000 with). */
  timeBudgetMs?: number;
  /** Max concurrent NVD requests (default: 1 without a key, 8 with). */
  concurrency?: number;
}

export interface NvdEnrichment {
  /** Same findings, with `sources`/`nvd` filled in where a CVE was matched. */
  vulnerabilities: ScanVulnerability[];
  warnings: string[];
  /** Number of findings that gained NVD data. */
  enrichedCount: number;
}

/**
 * Best-effort NVD cross-reference for every finding that carries a CVE id.
 * Serial without a key (the public rate window punishes bursts); with a key,
 * fetched concurrently under a larger budget so more CVEs are covered. Bounded
 * by a request cap and a time budget. Failures degrade to warnings — never
 * throws.
 */
export async function enrichWithNvd(
  vulnerabilities: ScanVulnerability[],
  options: NvdEnrichmentOptions = {}
): Promise<NvdEnrichment> {
  const apiKey = options.apiKey ?? process.env.NVD_API_KEY ?? undefined;
  const timeBudgetMs =
    options.timeBudgetMs ??
    (apiKey ? TIME_BUDGET_WITH_KEY_MS : TIME_BUDGET_WITHOUT_KEY_MS);
  const concurrency =
    options.concurrency ?? (apiKey ? CONCURRENCY_WITH_KEY : CONCURRENCY_WITHOUT_KEY);
  const maxFetches = apiKey ? MAX_CVES_WITH_KEY : MAX_CVES_WITHOUT_KEY;

  // Unique CVEs in severity order, so the budget is spent on the worst
  // findings first (input is already severity-sorted by the scan pipeline).
  const uniqueCves: string[] = [];
  for (const v of vulnerabilities) {
    if (v.cveId && !uniqueCves.includes(v.cveId)) uniqueCves.push(v.cveId);
  }
  if (uniqueCves.length === 0) {
    return { vulnerabilities, warnings: [], enrichedCount: 0 };
  }

  // Cached CVEs are free (no request, no budget); queue the rest up to the cap.
  const dataByCve = new Map<string, NvdData>();
  const toFetch: string[] = [];
  let cachedCount = 0;
  for (const cveId of uniqueCves) {
    if (nvdCache.has(cveId)) {
      cachedCount++;
      const data = nvdCache.get(cveId);
      if (data) dataByCve.set(cveId, data);
    } else if (toFetch.length < maxFetches) {
      toFetch.push(cveId);
    }
  }

  // Fetch with bounded concurrency; each request is capped by the remaining
  // budget, and once the deadline passes the rest are skipped (not attempted).
  const warnings: string[] = [];
  const deadline = Date.now() + timeBudgetMs;
  let failed = 0;
  let skipped = 0;
  await mapWithConcurrency(toFetch, concurrency, async (cveId) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      skipped++;
      return;
    }
    // Bound each request to the remaining budget so it can't overrun (with a
    // small floor so a near-deadline request still has a fair chance).
    const perRequest = Math.max(500, Math.min(REQUEST_TIMEOUT_MS, remaining));
    try {
      const data = await fetchNvdCve(cveId, apiKey, perRequest);
      if (data) dataByCve.set(cveId, data);
    } catch {
      failed++;
    }
  });

  const attempted = cachedCount + (toFetch.length - skipped);
  if (attempted < uniqueCves.length) {
    const hint = apiKey
      ? "best-effort within the NVD time budget"
      : "public NVD API rate limits — set NVD_API_KEY to raise coverage";
    warnings.push(
      `NVD cross-check covered ${attempted} of ${uniqueCves.length} CVEs (${hint}). Uncovered findings remain OSV-only.`
    );
  }
  if (failed > 0 && dataByCve.size === 0) {
    warnings.push(
      "NVD cross-check unavailable (the NVD API did not respond in time). All findings are OSV-only for this scan."
    );
  }

  let enrichedCount = 0;
  const enriched = vulnerabilities.map((v) => {
    const nvd = v.cveId ? dataByCve.get(v.cveId) : undefined;
    if (!nvd) return v;
    enrichedCount++;
    return { ...v, nvd, sources: ["osv", "nvd"] as ScanVulnerability["sources"] };
  });

  return { vulnerabilities: enriched, warnings, enrichedCount };
}
