import { fetchWithRetry, mapWithConcurrency } from "./http";

const OSV_BASE = "https://api.osv.dev/v1";

// Cap concurrent detail requests so a vuln-heavy repo doesn't fan out hundreds
// of simultaneous calls to OSV.
const OSV_DETAIL_CONCURRENCY = 8;

export interface OsvQuery {
  name: string;
  version: string;
}

/** Key used to index query results: the same package can be checked at more
 *  than one version (nested copies in a lock file tree). */
export function osvQueryKey(q: OsvQuery): string {
  return `${q.name}@${q.version}`;
}

export interface OsvSeverity {
  type: string;
  score: string;
}

export interface OsvAffectedRange {
  type: string;
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
}

export interface OsvAffected {
  package?: { name: string; ecosystem: string };
  ranges?: OsvAffectedRange[];
  versions?: string[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  database_specific?: Record<string, any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ecosystem_specific?: Record<string, any>;
}

export interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: Array<{ type: string; url: string }>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  database_specific?: Record<string, any>;
}

// ---------------------------------------------------------------------------
// Step 1 — querybatch: find which packages have vulns and collect their IDs.
// Results are keyed by osvQueryKey (name@version).
// ---------------------------------------------------------------------------
async function batchQueryIds(queries: OsvQuery[]): Promise<Map<string, string[]>> {
  const idsByPackage = new Map<string, string[]>();

  const CHUNK = 999;
  // Safety bound on pagination — a single npm name@version never approaches
  // this many advisories, but it prevents an unbounded loop on a bad token.
  const MAX_PAGES = 20;

  for (let i = 0; i < queries.length; i += CHUNK) {
    const chunk = queries.slice(i, i + CHUNK);

    // OSV returns a per-result `next_page_token` when a query matches more
    // advisories than fit in one page. Carry the tokened queries forward and
    // re-request until every result is exhausted, so heavily-affected packages
    // don't silently lose advisories.
    let pending = chunk.map((q) => ({ q, pageToken: undefined as string | undefined }));

    for (let page = 0; page < MAX_PAGES && pending.length > 0; page++) {
      const res = await fetchWithRetry(`${OSV_BASE}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: pending.map(({ q, pageToken }) => ({
            package: { name: q.name, ecosystem: "npm" },
            version: q.version,
            ...(pageToken ? { page_token: pageToken } : {}),
          })),
        }),
      });

      if (!res.ok) throw new Error(`OSV querybatch ${res.status}: ${await res.text()}`);

      const data = (await res.json()) as {
        results: Array<{ vulns?: Array<{ id: string }>; next_page_token?: string }>;
      };

      // Results align 1:1 with the queries just sent (`pending`).
      const next: typeof pending = [];
      data.results.forEach((result, idx) => {
        const { q } = pending[idx];
        const ids = result.vulns?.map((v) => v.id).filter(Boolean) ?? [];
        if (ids.length > 0) {
          const key = osvQueryKey(q);
          const existing = idsByPackage.get(key);
          idsByPackage.set(key, existing ? existing.concat(ids) : ids);
        }
        if (result.next_page_token) next.push({ q, pageToken: result.next_page_token });
      });
      pending = next;
    }
  }

  return idsByPackage;
}

// ---------------------------------------------------------------------------
// Step 2 — fetch full vuln details for every unique ID
// ---------------------------------------------------------------------------
async function fetchVulnById(id: string): Promise<OsvVuln | null> {
  try {
    const res = await fetchWithRetry(`${OSV_BASE}/vulns/${id}`);
    if (!res.ok) return null;
    return (await res.json()) as OsvVuln;
  } catch {
    return null;
  }
}

async function fetchAllVulnDetails(ids: string[]): Promise<Map<string, OsvVuln>> {
  const details = new Map<string, OsvVuln>();
  if (ids.length === 0) return details;

  // Bounded concurrency — typical repos have < 50 unique vulns, but cap the
  // fan-out so large ones don't hammer OSV.
  const fetched = await mapWithConcurrency(ids, OSV_DETAIL_CONCURRENCY, (id) =>
    fetchVulnById(id)
  );
  ids.forEach((id, i) => {
    const vuln = fetched[i];
    if (vuln) details.set(id, vuln);
  });

  return details;
}

/**
 * Query every OSV advisory for a single package (optionally scoped to one
 * version) via POST /v1/query. Unlike querybatch this returns full records in
 * one round trip — right for single-package verdicts (CLI/MCP `check`).
 * Only the first page is read: a package with >1 page of advisories has
 * long since crossed every verdict threshold anyway.
 */
export async function queryOsvPackage(
  name: string,
  version?: string | null
): Promise<OsvVuln[]> {
  const res = await fetchWithRetry(`${OSV_BASE}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      package: { name, ecosystem: "npm" },
      ...(version ? { version } : {}),
    }),
  });
  if (!res.ok) throw new Error(`OSV query ${res.status}: ${await res.text()}`);
  const data = (await res.json()) as { vulns?: OsvVuln[] };
  return data.vulns ?? [];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
export interface OsvQueryResult {
  /** Full vulnerability records keyed by {@link osvQueryKey} (name@version). */
  results: Map<string, OsvVuln[]>;
  /** Non-fatal issues (e.g. detail lookups that failed). */
  warnings: string[];
}

export async function queryOsvBatch(queries: OsvQuery[]): Promise<OsvQueryResult> {
  if (queries.length === 0) return { results: new Map(), warnings: [] };

  const idsByPackage = await batchQueryIds(queries);
  const uniqueIds = [...new Set([...idsByPackage.values()].flat())];
  const details = await fetchAllVulnDetails(uniqueIds);

  const warnings: string[] = [];
  const failed = uniqueIds.filter((id) => !details.has(id));
  if (failed.length > 0) {
    warnings.push(
      `Could not fetch full details for ${failed.length} of ${uniqueIds.length} vulnerabilities from OSV. These were omitted from the report.`
    );
  }

  const results = new Map<string, OsvVuln[]>();
  for (const [pkgName, ids] of idsByPackage) {
    const vulns = ids
      .map((id) => details.get(id))
      .filter((v): v is OsvVuln => v !== undefined);
    if (vulns.length > 0) results.set(pkgName, vulns);
  }

  return { results, warnings };
}
