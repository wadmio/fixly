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
      cache: "no-store",
    });

    if (!res.ok) throw new Error(`OSV querybatch ${res.status}: ${await res.text()}`);

    const data: { results: Array<{ vulns?: Array<{ id: string }> }> } =
      await res.json();

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
    const res = await fetch(`${OSV_BASE}/vulns/${id}`, { cache: "no-store" });
    if (!res.ok) return null;
    return res.json();
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
export async function queryOsvBatch(
  packages: PackageEntry[]
): Promise<Map<string, OsvVuln[]>> {
  if (packages.length === 0) return new Map();

  // 1. Identify which packages have vulns (returns IDs only)
  const idsByPackage = await batchQueryIds(packages);

  // 2. Collect unique IDs across all packages
  const uniqueIds = [
    ...new Set([...idsByPackage.values()].flat()),
  ];

  // 3. Fetch full details for each unique vuln
  const details = await fetchAllVulnDetails(uniqueIds);

  // 4. Re-map full vulns back to their packages
  const results = new Map<string, OsvVuln[]>();
  for (const [pkgName, ids] of idsByPackage) {
    const vulns = ids
      .map((id) => details.get(id))
      .filter((v): v is OsvVuln => v !== undefined);
    if (vulns.length > 0) results.set(pkgName, vulns);
  }

  return results;
}
