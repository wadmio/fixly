// npm registry metadata client — the "who is this package, really?" signals:
// does it exist, how old is it, is anyone using it, is it deprecated, does it
// run install scripts. All public, unauthenticated endpoints.
//
// Popular packages (see popular-packages.ts) are typically skipped by callers:
// their packuments are megabytes and their legitimacy isn't in question. The
// obscure/new packages this module exists for have tiny packuments.

import { fetchWithRetry } from "./http";

const REGISTRY_BASE = "https://registry.npmjs.org";
const DOWNLOADS_BASE = "https://api.npmjs.org/downloads/point/last-week";
const REQUEST_TIMEOUT_MS = 5_000;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1h — registry metadata moves slowly

export interface RegistryInfo {
  exists: boolean;
  /** Days since the package was first published (null if unknown). */
  ageDays: number | null;
  /** Days since the most recent publish (null if unknown). */
  lastPublishDays: number | null;
  latestVersion: string | null;
  /** True when the requested version exists (null when no version asked). */
  versionExists: boolean | null;
  deprecated: boolean;
  /** True when the (requested or latest) version declares install hooks. */
  hasInstallScripts: boolean | null;
  maintainers: number | null;
  weeklyDownloads: number | null;
}

const cache = new Map<string, { at: number; info: RegistryInfo }>();

/** Test hook / manual reset. */
export function clearRegistryCache(): void {
  cache.clear();
}

function daysSince(iso: string | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86_400_000));
}

interface Packument {
  "dist-tags"?: Record<string, string>;
  time?: Record<string, string>;
  maintainers?: Array<unknown>;
  versions?: Record<
    string,
    {
      deprecated?: string;
      hasInstallScript?: boolean;
      scripts?: Record<string, string>;
    }
  >;
}

const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];

async function fetchWeeklyDownloads(name: string): Promise<number | null> {
  try {
    const res = await fetchWithRetry(
      `${DOWNLOADS_BASE}/${encodeURIComponent(name).replace(/^%40/, "@")}`,
      { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
      { retries: 1 }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { downloads?: number };
    return typeof data.downloads === "number" ? data.downloads : null;
  } catch {
    return null;
  }
}

/**
 * Resolve just the latest published version via the tiny `/<pkg>/latest`
 * endpoint (single-version metadata — small even for react-sized packages).
 * Returns null when the package doesn't exist; throws on network trouble.
 */
export async function fetchLatestVersion(name: string): Promise<string | null> {
  const res = await fetchWithRetry(
    `${REGISTRY_BASE}/${name.replace("/", "%2F")}/latest`,
    { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
    { retries: 1 }
  );
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`npm registry ${res.status} for ${name}@latest`);
  const data = (await res.json()) as { version?: string };
  return data.version ?? null;
}

/**
 * Look up a package's registry profile. A definitive 404 → `exists: false`
 * (the hallucination/slopsquat signal). Network trouble throws — callers
 * must distinguish "does not exist" from "could not check".
 */
export async function fetchRegistryInfo(
  name: string,
  version?: string | null
): Promise<RegistryInfo> {
  const cacheKey = `${name}@${version ?? ""}`;
  const hit = cache.get(cacheKey);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.info;

  const res = await fetchWithRetry(
    `${REGISTRY_BASE}/${name.replace("/", "%2F")}`,
    { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
    { retries: 1 }
  );

  if (res.status === 404) {
    const info: RegistryInfo = {
      exists: false,
      ageDays: null,
      lastPublishDays: null,
      latestVersion: null,
      versionExists: version ? false : null,
      deprecated: false,
      hasInstallScripts: null,
      maintainers: null,
      weeklyDownloads: null,
    };
    cache.set(cacheKey, { at: Date.now(), info });
    return info;
  }
  if (!res.ok) throw new Error(`npm registry ${res.status} for ${name}`);

  const pack = (await res.json()) as Packument;
  const latestVersion = pack["dist-tags"]?.latest ?? null;
  const inspected = version && pack.versions?.[version] ? version : latestVersion;
  const versionMeta = inspected ? pack.versions?.[inspected] : undefined;

  const hasInstallScripts =
    versionMeta === undefined
      ? null
      : versionMeta.hasInstallScript === true ||
        INSTALL_HOOKS.some((h) => versionMeta.scripts?.[h] !== undefined);

  const info: RegistryInfo = {
    exists: true,
    ageDays: daysSince(pack.time?.created),
    lastPublishDays: daysSince(pack.time?.modified),
    latestVersion,
    versionExists: version ? pack.versions?.[version] !== undefined : null,
    deprecated: typeof versionMeta?.deprecated === "string",
    hasInstallScripts,
    maintainers: Array.isArray(pack.maintainers) ? pack.maintainers.length : null,
    weeklyDownloads: await fetchWeeklyDownloads(name),
  };
  cache.set(cacheKey, { at: Date.now(), info });
  return info;
}
