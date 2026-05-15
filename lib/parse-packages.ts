import type { PackageEntry } from "./types";

/**
 * Strip semver range operators and return a plain version string,
 * or null if the value is not resolvable to a specific version.
 */
function cleanVersion(raw: string): string | null {
  if (!raw || raw === "*" || raw === "") return null;
  // Handle "latest", "next", etc.
  if (/^[a-zA-Z]/.test(raw) && !raw.startsWith("v")) return null;
  const cleaned = raw.replace(/^[\^~>=<v\s]+/, "").split(/\s+/)[0].split("||")[0].trim();
  // Must look like a semver (at least major.minor)
  if (!/^\d+\.\d+/.test(cleaned)) return null;
  return cleaned;
}

/**
 * Extract resolved versions from a package-lock.json (v1, v2, or v3).
 * Only top-level node_modules entries are used (no nested deps).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractLockVersions(packageLock: any): Record<string, string> {
  const resolved: Record<string, string> = {};

  if (!packageLock) return resolved;

  if (packageLock.lockfileVersion >= 2 && packageLock.packages) {
    for (const [key, val] of Object.entries(
      packageLock.packages as Record<string, { version?: string }>
    )) {
      // Skip root entry ("") and nested node_modules
      if (!key.startsWith("node_modules/")) continue;
      if (key.includes("/node_modules/")) continue;
      const name = key.slice("node_modules/".length);
      if (val.version) resolved[name] = val.version;
    }
  } else if (packageLock.dependencies) {
    for (const [name, val] of Object.entries(
      packageLock.dependencies as Record<string, { version?: string }>
    )) {
      if (val.version) resolved[name] = val.version;
    }
  }

  return resolved;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parsePackages(packageJson: any, packageLock: any | null): PackageEntry[] {
  const resolved = extractLockVersions(packageLock);
  const packages = new Map<string, PackageEntry>();

  function addDeps(deps: Record<string, string> | undefined, isDev: boolean) {
    if (!deps) return;
    for (const [name, versionRange] of Object.entries(deps)) {
      const version = resolved[name] ?? cleanVersion(versionRange);
      if (version) {
        packages.set(name, { name, version, isDev });
      }
    }
  }

  addDeps(packageJson.dependencies, false);
  addDeps(packageJson.devDependencies, true);

  return Array.from(packages.values());
}
