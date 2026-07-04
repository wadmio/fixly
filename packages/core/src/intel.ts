// Exploit intelligence — turns "a list of CVEs" into "which ones matter".
//
// Free, authoritative feeds, stamped onto findings that carry a CVE:
//   - CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed
//     exploitation in the wild — binary, high-signal, "fix this NOW". We also
//     read `dateAdded` to flag *newly* known-exploited CVEs.
//   - VulnCheck KEV (community, opt-in via VULNCHECK_API_KEY): a wider,
//     faster-moving exploited-in-the-wild catalog (~175% of CISA's size). When
//     a key is present we union it into the KEV set.
//   - FIRST EPSS: a daily ML-derived probability (0–1) a CVE is exploited in
//     the next 30 days. We consume EPSS rather than reinventing it.
//   - nomi-sec PoC-in-GitHub: how many public proof-of-concept exploit repos
//     exist for a CVE — the "exploit code is one copy-paste away" signal that
//     sits between EPSS prediction and confirmed KEV exploitation.
//
// Every enrichment is best-effort: failures degrade (KEV/EPSS to a warning; the
// supplementary PoC feed silently) and findings keep their OSV data. Nothing
// here ever fails a scan. Disable the whole stage with FIXLY_DISABLE_INTEL=1.

import { fetchWithRetry, mapWithConcurrency } from "./http";
import { BoundedMap } from "./bounded-map";
import type { ScanVulnerability } from "./types";

// Re-export the pure KEV freshness helpers (defined in the client-safe ./kev
// module) so existing `from "./intel"` / barrel imports keep working.
export { kevAgeDays, isNewlyExploited } from "./kev";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev";
const EPSS_URL = "https://api.first.org/data/v1/epss";
const POC_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master";
const REQUEST_TIMEOUT_MS = 6_000;
const KEV_TTL_MS = 24 * 60 * 60 * 1000; // CISA updates the catalog ~weekly
const EPSS_CHUNK = 100;
const POC_MAX_CVES = 40; // cap PoC lookups per scan (best-effort, severity-first)
const POC_CONCURRENCY = 8;

interface KevEntry {
  /** ISO date the CVE entered a KEV catalog, or null if unknown. */
  dateAdded: string | null;
}

let kevCache: { at: number; map: Map<string, KevEntry> } | null = null;
// Capped so a long-lived server can't accumulate entries without bound.
const epssCache = new BoundedMap<string, { score: number; percentile: number }>(10000);
const pocCache = new BoundedMap<string, number>(5000);

/** Test hook / manual reset. */
export function clearIntelCache(): void {
  kevCache = null;
  epssCache.clear();
  pocCache.clear();
}

async function fetchKevCatalog(): Promise<Map<string, KevEntry>> {
  if (kevCache && Date.now() - kevCache.at < KEV_TTL_MS) return kevCache.map;

  const map = new Map<string, KevEntry>();

  // CISA KEV — always, no key required.
  const res = await fetchWithRetry(KEV_URL, undefined, {
    retries: 1,
    timeoutMs: REQUEST_TIMEOUT_MS,
  });
  if (!res.ok) throw new Error(`KEV catalog ${res.status}`);
  const data = (await res.json()) as {
    vulnerabilities?: Array<{ cveID?: string; dateAdded?: string }>;
  };
  for (const v of data.vulnerabilities ?? []) {
    if (v.cveID) map.set(v.cveID, { dateAdded: v.dateAdded ?? null });
  }

  // VulnCheck community KEV — opt-in, wider/faster than CISA. Best-effort: a
  // failure here still leaves the full CISA catalog intact.
  const vcKey = process.env.VULNCHECK_API_KEY;
  if (vcKey) {
    try {
      await mergeVulnCheckKev(map, vcKey);
    } catch {
      /* keep CISA-only */
    }
  }

  kevCache = { at: Date.now(), map };
  return map;
}

/**
 * Merge the VulnCheck community KEV index into `map`. Paginated; pulls up to a
 * page cap and keeps the EARLIEST known dateAdded per CVE (VulnCheck often lists
 * exploitation before CISA does). Note: exercised only when VULNCHECK_API_KEY is
 * set; the pagination shape follows VulnCheck's documented `data`/`_meta` index.
 */
async function mergeVulnCheckKev(map: Map<string, KevEntry>, apiKey: string): Promise<void> {
  const LIMIT = 200;
  const MAX_PAGES = 30; // ~6000 entries — comfortably above the catalog size
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await fetchWithRetry(
      `${VULNCHECK_KEV_URL}?limit=${LIMIT}&page=${page}`,
      { headers: { Authorization: `Bearer ${apiKey}` } },
      { retries: 1, timeoutMs: REQUEST_TIMEOUT_MS }
    );
    if (!res.ok) throw new Error(`VulnCheck KEV ${res.status}`);
    const body = (await res.json()) as {
      data?: Array<{ cve?: string[]; date_added?: string }>;
      _meta?: { total_pages?: number };
    };
    for (const item of body.data ?? []) {
      const date = item.date_added ?? null;
      for (const cve of item.cve ?? []) {
        const existing = map.get(cve);
        if (!existing) {
          map.set(cve, { dateAdded: date });
        } else if (date && (!existing.dateAdded || date < existing.dateAdded)) {
          map.set(cve, { dateAdded: date }); // earliest known
        }
      }
    }
    const totalPages = body._meta?.total_pages ?? page;
    if (page >= totalPages || (body.data?.length ?? 0) === 0) break;
  }
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
    const res = await fetchWithRetry(`${EPSS_URL}?cve=${chunk.join(",")}`, undefined, {
      retries: 1,
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
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

function pocUrl(cve: string): string | null {
  const m = /^CVE-(\d{4})-\d+$/.exec(cve);
  return m ? `${POC_BASE}/${m[1]}/${cve}.json` : null;
}

async function fetchPocCount(cve: string): Promise<number | null> {
  const url = pocUrl(cve);
  if (!url) return null;
  try {
    const res = await fetchWithRetry(url, undefined, { retries: 1, timeoutMs: REQUEST_TIMEOUT_MS });
    if (res.status === 404) return 0; // no PoC file for this CVE
    if (!res.ok) return null;
    const data = (await res.json()) as unknown;
    return Array.isArray(data) ? data.length : 0;
  } catch {
    return null;
  }
}

/** Public PoC counts for up to POC_MAX_CVES CVEs (severity-first input order),
 *  bounded concurrency + module cache. Never throws — missing data → no entry. */
async function fetchPocCounts(cves: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const missing: string[] = [];
  for (const cve of cves) {
    const hit = pocCache.get(cve);
    if (hit !== undefined) out.set(cve, hit);
    else missing.push(cve);
  }
  const toFetch = missing.slice(0, POC_MAX_CVES);
  const counts = await mapWithConcurrency(toFetch, POC_CONCURRENCY, (cve) => fetchPocCount(cve));
  toFetch.forEach((cve, i) => {
    const c = counts[i];
    if (c !== null) {
      pocCache.set(cve, c);
      out.set(cve, c);
    }
  });
  return out;
}

export interface IntelEnrichment {
  vulnerabilities: ScanVulnerability[];
  warnings: string[];
}

/**
 * Stamp exploit intelligence onto every finding that has a CVE: `knownExploited`
 * + `kevDateAdded` (CISA/VulnCheck KEV), `epssScore`/`epssPercentile` (EPSS), and
 * `pocCount` (public PoC repos). Best-effort — KEV/EPSS failures warn; the
 * supplementary PoC feed degrades silently.
 */
export async function enrichWithIntel(
  vulnerabilities: ScanVulnerability[]
): Promise<IntelEnrichment> {
  const cves = [...new Set(vulnerabilities.map((v) => v.cveId).filter((c): c is string => !!c))];
  if (cves.length === 0) return { vulnerabilities, warnings: [] };

  const warnings: string[] = [];
  let kev: Map<string, KevEntry> | null = null;
  let epss: Map<string, { score: number; percentile: number }> | null = null;
  let poc: Map<string, number> | null = null;

  try {
    kev = await fetchKevCatalog();
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
  // Supplementary — never warns (nomi-sec is a community mirror; absence just
  // means no PoC data, not a scan problem).
  poc = await fetchPocCounts(cves);

  if (!kev && !epss && (!poc || poc.size === 0)) return { vulnerabilities, warnings };

  const enriched = vulnerabilities.map((v) => {
    if (!v.cveId) return v;
    const kevEntry = kev?.get(v.cveId);
    const epssEntry = epss?.get(v.cveId);
    const pocCount = poc?.get(v.cveId);
    return {
      ...v,
      knownExploited: kevEntry ? true : v.knownExploited,
      kevDateAdded: kevEntry?.dateAdded ?? v.kevDateAdded,
      epssScore: epssEntry?.score ?? v.epssScore,
      epssPercentile: epssEntry?.percentile ?? v.epssPercentile,
      pocCount: pocCount ?? v.pocCount,
    };
  });

  return { vulnerabilities: enriched, warnings };
}
