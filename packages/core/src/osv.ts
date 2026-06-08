import type { PackageEntry } from "./types";

const OSV_BASE = "https://api.osv.dev/v1";

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
// Step 1 — querybatch: find which packages have vulns and collect their IDs
// ---------------------------------------------------------------------------
async function batchQueryIds(
  packages: PackageEntry[]
): Promise<Map<string, string[]>> {
  const idsByPackage = new Map<string, string[]>();

  const CHUNK = 999;
  for (let i = 0; i < packages.length; i += CHUNK) {
    const chunk = packages.slice(i, i + CHUNK);

    const res = await fetch(`${OSV_BASE}/querybatch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: chunk.map((pkg) => ({
          package: { name: pkg.name, ecosystem: "npm" },
          version: pkg.version,
        })),
      }),
    });

    if (!res.ok) throw new Error(`OSV querybatch ${res.status}: ${await res.text()}`);

    const data = (await res.json()) as {
      results: Array<{ vulns?: Array<{ id: string }> }>;
    };

    data.results.forEach((result, idx) => {
      const ids = result.vulns?.map((v) => v.id).filter(Boolean) ?? [];
      if (ids.length > 0) {
        idsByPackage.set(chunk[idx].name, ids);
      }
    });
  }

  return idsByPackage;
}

// ---------------------------------------------------------------------------
// Step 2 — fetch full vuln details for every unique ID
// ---------------------------------------------------------------------------
async function fetchVulnById(id: string): Promise<OsvVuln | null> {
  try {
    const res = await fetch(`${OSV_BASE}/vulns/${id}`);
    if (!res.ok) return null;
    return (await res.json()) as OsvVuln;
  } catch {
    return null;
  }
}

async function fetchAllVulnDetails(
  ids: string[]
): Promise<Map<string, OsvVuln>> {
  const details = new Map<string, OsvVuln>();
  if (ids.length === 0) return details;

  // Fetch all in parallel — typical repos have < 50 unique vulns
  const settled = await Promise.allSettled(
    ids.map((id) => fetchVulnById(id).then((v) => ({ id, v })))
  );

  for (const result of settled) {
    if (result.status === "fulfilled" && result.value.v) {
      details.set(result.value.id, result.value.v);
    }
  }

  return details;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
export interface OsvQueryResult {
  /** Full vulnerability records keyed by package name. */
  results: Map<string, OsvVuln[]>;
  /** Non-fatal issues (e.g. detail lookups that failed). */
  warnings: string[];
}

export async function queryOsvBatch(
  packages: PackageEntry[]
): Promise<OsvQueryResult> {
  if (packages.length === 0) return { results: new Map(), warnings: [] };

  // 1. Identify which packages have vulns (returns IDs only)
  const idsByPackage = await batchQueryIds(packages);

  // 2. Collect unique IDs across all packages
  const uniqueIds = [
    ...new Set([...idsByPackage.values()].flat()),
  ];

  // 3. Fetch full details for each unique vuln
  const details = await fetchAllVulnDetails(uniqueIds);

  const warnings: string[] = [];
  const failed = uniqueIds.filter((id) => !details.has(id));
  if (failed.length > 0) {
    warnings.push(
      `Could not fetch full details for ${failed.length} of ${uniqueIds.length} vulnerabilities from OSV. These were omitted from the report.`
    );
  }

  // 4. Re-map full vulns back to their packages
  const results = new Map<string, OsvVuln[]>();
  for (const [pkgName, ids] of idsByPackage) {
    const vulns = ids
      .map((id) => details.get(id))
      .filter((v): v is OsvVuln => v !== undefined);
    if (vulns.length > 0) results.set(pkgName, vulns);
  }

  return { results, warnings };
}
