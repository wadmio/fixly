// Exploit intelligence — turns "a list of CVEs" into "which ones matter".
//
// Two free, authoritative feeds:
//   - CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed
//     exploitation in the wild. Binary, high-signal — "fix this NOW".
//   - EPSS (Exploit Prediction Scoring System, FIRST.org): a daily ML-derived
//     probability (0–1) that a CVE is exploited in the next 30 days. We
//     consume EPSS rather than reinventing it — it IS the ML model.
//
// Both enrichments are best-effort: failures degrade to a warning and findings
// keep their OSV data. Nothing here ever fails a scan.

import { fetchWithRetry } from "./http";
import type { ScanVulnerability } from "./types";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const REQUEST_TIMEOUT_MS = 6_000;
const KEV_TTL_MS = 24 * 60 * 60 * 1000; // CISA updates the catalog ~weekly
const EPSS_CHUNK = 100;

let kevCache: { at: number; cves: Set<string> } | null = null;
const epssCache = new Map<string, { score: number; percentile: number }>();

/** Test hook / manual reset. */
export function clearIntelCache(): void {
  kevCache = null;
  epssCache.clear();
}

async function fetchKevSet(): Promise<Set<string>> {
  if (kevCache && Date.now() - kevCache.at < KEV_TTL_MS) return kevCache.cves;
  const res = await fetchWithRetry(
    KEV_URL,
    { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
    { retries: 1 }
  );
  if (!res.ok) throw new Error(`KEV catalog ${res.status}`);
  const data = (await res.json()) as { vulnerabilities?: Array<{ cveID?: string }> };
  const cves = new Set<string>();
  for (const v of data.vulnerabilities ?? []) {
    if (v.cveID) cves.add(v.cveID);
  }
  kevCache = { at: Date.now(), cves };
  return cves;
}

async function fetchEpssScores(
  cves: string[]
): Promise<Map<string, { score: number; percentile: number }>> {
  const out = new Map<string, { score: number; percentile: number }>();
  const missing: string[] = [];
  for (const cve of cves) {
    const hit = epssCache.get(cve);
    if (hit) out.set(cve, hit);
    else missing.push(cve);
  }

  for (let i = 0; i < missing.length; i += EPSS_CHUNK) {
    const chunk = missing.slice(i, i + EPSS_CHUNK);
    const res = await fetchWithRetry(
      `${EPSS_URL}?cve=${chunk.join(",")}`,
      { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
      { retries: 1 }
    );
    if (!res.ok) throw new Error(`EPSS API ${res.status}`);
    const data = (await res.json()) as {
      data?: Array<{ cve?: string; epss?: string; percentile?: string }>;
    };
    for (const row of data.data ?? []) {
      if (!row.cve) continue;
      const entry = { score: Number(row.epss ?? 0), percentile: Number(row.percentile ?? 0) };
      epssCache.set(row.cve, entry);
      out.set(row.cve, entry);
    }
  }
  return out;
}

export interface IntelEnrichment {
  vulnerabilities: ScanVulnerability[];
  warnings: string[];
}

/**
 * Stamp `knownExploited` (CISA KEV) and `epssScore`/`epssPercentile` (FIRST
 * EPSS) onto every finding that has a CVE. Best-effort — degrades to warnings.
 */
export async function enrichWithIntel(
  vulnerabilities: ScanVulnerability[]
): Promise<IntelEnrichment> {
  const cves = [...new Set(vulnerabilities.map((v) => v.cveId).filter((c): c is string => !!c))];
  if (cves.length === 0) return { vulnerabilities, warnings: [] };

  const warnings: string[] = [];
  let kev: Set<string> | null = null;
  let epss: Map<string, { score: number; percentile: number }> | null = null;

  try {
    kev = await fetchKevSet();
  } catch {
    warnings.push(
      "Could not reach the CISA KEV catalog — known-exploited flags are unavailable for this scan."
    );
  }
  try {
    epss = await fetchEpssScores(cves);
  } catch {
    warnings.push(
      "Could not reach the EPSS API — exploit-probability scores are unavailable for this scan."
    );
  }

  if (!kev && !epss) return { vulnerabilities, warnings };

  const enriched = vulnerabilities.map((v) => {
    if (!v.cveId) return v;
    const epssEntry = epss?.get(v.cveId);
    const knownExploited = kev?.has(v.cveId) ?? v.knownExploited;
    if (!epssEntry && knownExploited === v.knownExploited) return v;
    return {
      ...v,
      knownExploited,
      epssScore: epssEntry?.score ?? v.epssScore,
      epssPercentile: epssEntry?.percentile ?? v.epssPercentile,
    };
  });

  return { vulnerabilities: enriched, warnings };
}
