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

import { fetchWithRetry } from "./http";
import type { NvdData, ScanVulnerability, Severity } from "./types";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/** Max CVEs fetched per scan, respecting NVD's public rate windows. */
const MAX_CVES_WITHOUT_KEY = 5;
const MAX_CVES_WITH_KEY = 40;
/** Per-request timeout — a slow NVD must never stall the scan. */
const REQUEST_TIMEOUT_MS = 4_000;
/** Overall enrichment budget per scan. */
const DEFAULT_TIME_BUDGET_MS = 8_000;

// CVE → NvdData (or null when NVD had no usable CVSS data for it). Module-level
// so rescans and demo repeats hit the cache instead of the rate limit.
const nvdCache = new Map<string, NvdData | null>();

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

async function fetchNvdCve(cveId: string, apiKey: string | undefined): Promise<NvdData | null> {
  const cached = nvdCache.get(cveId);
  if (cached !== undefined) return cached;

  const res = await fetchWithRetry(
    `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`,
    {
      headers: apiKey ? { apiKey } : undefined,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    },
    // One retry only — NVD 429s are long-window; better to move on than stall.
    { retries: 1, baseDelayMs: 500, maxDelayMs: 1_500 }
  );
  if (!res.ok) throw new Error(`NVD ${res.status}`);

  const data = parseNvdResponse((await res.json()) as NvdCveResponse);
  nvdCache.set(cveId, data);
  return data;
}

export interface NvdEnrichmentOptions {
  /** Overrides the NVD_API_KEY environment variable. */
  apiKey?: string;
  /** Overall time budget in ms (default 8000). */
  timeBudgetMs?: number;
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
 * Sequential requests (NVD's rolling rate windows punish bursts), bounded by a
 * request cap and a time budget. Failures degrade to warnings — never throws.
 */
export async function enrichWithNvd(
  vulnerabilities: ScanVulnerability[],
  options: NvdEnrichmentOptions = {}
): Promise<NvdEnrichment> {
  const apiKey = options.apiKey ?? process.env.NVD_API_KEY ?? undefined;
  const timeBudgetMs = options.timeBudgetMs ?? DEFAULT_TIME_BUDGET_MS;
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

  const dataByCve = new Map<string, NvdData>();
  const warnings: string[] = [];
  const deadline = Date.now() + timeBudgetMs;
  let fetches = 0;
  let failed = 0;
  let attempted = 0;

  for (const cveId of uniqueCves) {
    const isCached = nvdCache.has(cveId);
    if (!isCached && (fetches >= maxFetches || Date.now() >= deadline)) break;
    attempted++;
    try {
      if (!isCached) fetches++;
      const data = await fetchNvdCve(cveId, apiKey);
      if (data) dataByCve.set(cveId, data);
    } catch {
      failed++;
    }
  }

  if (attempted < uniqueCves.length) {
    warnings.push(
      `NVD cross-check covered ${attempted} of ${uniqueCves.length} CVEs (public NVD API rate limits — set NVD_API_KEY to raise coverage). Uncovered findings remain OSV-only.`
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
