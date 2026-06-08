import type { DependencyEntry, DependencyType } from "./types";

export interface ParsedDependencies {
  dependencies: DependencyEntry[];
  warnings: string[];
}

/**
 * Strip semver range operators (^ ~ >= < v, whitespace) and return a plain
 * version string, or null if the value cannot be resolved to a concrete version
 * (e.g. "*", "latest", a dist-tag, or a git/url specifier).
 */
function cleanVersion(raw: string): string | null {
  if (!raw || raw === "*" || raw === "") return null;
  // "latest", "next", git URLs, file:, etc. are not concrete versions.
  if (/^[a-zA-Z]/.test(raw) && !raw.startsWith("v")) return null;
  const cleaned = raw.replace(/^[\^~>=<v\s]+/, "").split(/\s+/)[0].split("||")[0].trim();
  // Must look like a semver (at least major.minor).
  if (!/^\d+\.\d+/.test(cleaned)) return null;
  return cleaned;
}

/**
 * The concrete version to check against OSV for a dependency: the exact lock
 * version when known, otherwise the resolved minimum of the requested range.
 * Returns null when neither can be determined (caller should skip + warn).
 */
export function resolveCheckVersion(entry: DependencyEntry): string | null {
  return entry.installedVersion ?? cleanVersion(entry.requestedVersion);
}

/**
 * Extract resolved versions from a package-lock.json (v1, v2, or v3).
 * Only top-level node_modules entries are used (no nested/transitive deps).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractLockVersions(packageLock: any): Record<string, string> {
  const resolved: Record<string, string> = {};
  if (!packageLock) return resolved;

  if (packageLock.lockfileVersion >= 2 && packageLock.packages) {
    // v2 / v3: keyed by install path under node_modules/.
    for (const [key, val] of Object.entries(
      packageLock.packages as Record<string, { version?: string }>
    )) {
      if (!key.startsWith("node_modules/")) continue; // skip root ("")
      if (key.includes("/node_modules/")) continue; // skip nested deps
      const name = key.slice("node_modules/".length);
      if (val.version) resolved[name] = val.version;
    }
  } else if (packageLock.dependencies) {
    // v1: flat dependencies map.
    for (const [name, val] of Object.entries(
      packageLock.dependencies as Record<string, { version?: string }>
    )) {
      if (val.version) resolved[name] = val.version;
    }
  }

  return resolved;
}

/**
 * Resolve the direct dependencies of a package.json into normalized
 * {@link DependencyEntry} objects, preferring exact versions from the lock file.
 * Only direct `dependencies` + `devDependencies` are considered (no transitive).
 * Returns the entries plus non-fatal warnings (missing lock file, unresolvable
 * version ranges). `dependencies` take precedence over `devDependencies` when a
 * package appears in both.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseDependencies(packageJson: any, packageLock: any | null): ParsedDependencies {
  const resolved = extractLockVersions(packageLock);
  const dependencies: DependencyEntry[] = [];
  const seen = new Set<string>();
  const unresolved: string[] = [];
  const warnings: string[] = [];

  function add(deps: Record<string, string> | undefined, dependencyType: DependencyType) {
    if (!deps) return;
    for (const [name, requested] of Object.entries(deps)) {
      if (seen.has(name)) continue;
      seen.add(name);
      const requestedVersion = String(requested);
      const installedVersion = resolved[name] ?? null;
      const entry: DependencyEntry = {
        name,
        requestedVersion,
        installedVersion,
        dependencyType,
        sourceFile: "package.json",
      };
      dependencies.push(entry);
      if (resolveCheckVersion(entry) === null) unresolved.push(name);
    }
  }

  add(packageJson?.dependencies, "dependencies");
  add(packageJson?.devDependencies, "devDependencies");

  if (!packageLock) {
    warnings.push(
      "No package-lock.json found. Exact installed versions are unknown; each declared range was resolved to its minimum version, so results may be approximate."
    );
  }
  if (unresolved.length > 0) {
    warnings.push(
      `Could not determine a version to check for ${unresolved.length} package(s): ${unresolved.join(", ")}. These were skipped.`
    );
  }

  return { dependencies, warnings };
}
