// Lock-file dependency graph — implements the resolution engine's
// DependencyGraph boundary over a package-lock.json v2/v3 `packages` map.
//
// Only v2/v3 locks carry the edges we need (each entry declares the ranges it
// requests); v1 locks and absent locks return null, and the resolution engine
// then skips dependent-constraint checks and says so in its rationale.
//
// Pure data structure: no network, no fs — buildable from a parsed lock
// object in tests.

import type { DependencyGraph, DependentEdge } from "./resolution";

interface GraphNode {
  /** Install path, e.g. "node_modules/a/node_modules/b"; "" is the root. */
  path: string;
  /** Package name (segment after the last "node_modules/"); "(root)" for "". */
  name: string;
  version: string | null;
  /** Ranges this node declares: dependencies + peerDependencies (root also
   *  contributes devDependencies — they install at the top level too). */
  ranges: Record<string, string>;
}

interface LockPackageEntry {
  version?: string;
  link?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** The name encoded in an install path: everything after the last
 *  "node_modules/" (handles scoped names like "@scope/pkg"). */
function nameFromPath(path: string): string {
  const marker = path.lastIndexOf("node_modules/");
  return marker === -1 ? path : path.slice(marker + "node_modules/".length);
}

export class LockDependencyGraph implements DependencyGraph {
  private nodes = new Map<string, GraphNode>();

  constructor(packages: Record<string, LockPackageEntry>) {
    for (const [path, entry] of Object.entries(packages)) {
      if (path !== "" && !path.startsWith("node_modules/")) continue; // workspaces
      if (entry.link) continue; // workspace symlinks — not real installs

      const isRoot = path === "";
      const ranges: Record<string, string> = {
        ...(entry.peerDependencies ?? {}),
        ...(entry.dependencies ?? {}),
        ...(isRoot ? entry.devDependencies ?? {} : {}),
      };
      this.nodes.set(path, {
        path,
        name: isRoot ? "(root)" : nameFromPath(path),
        version: entry.version ?? null,
        ranges,
      });
    }
  }

  /** Which installed copy `depName` resolves to from `fromPath`, using npm's
   *  nearest-node_modules rule: check the node's own node_modules, then walk
   *  up one nesting level at a time to the top. Returns the node, or null. */
  private resolve(fromPath: string, depName: string): GraphNode | null {
    let p = fromPath;
    for (;;) {
      const key = p === "" ? `node_modules/${depName}` : `${p}/node_modules/${depName}`;
      const node = this.nodes.get(key);
      if (node) return node;
      if (p === "") return null;
      const idx = p.lastIndexOf("/node_modules/");
      p = idx === -1 ? "" : p.slice(0, idx);
    }
  }

  /** Every package (or "(root)") whose declared range on `name` resolves to
   *  the installed copy at `version`. */
  dependentsOf(name: string, version: string): DependentEdge[] {
    const edges: DependentEdge[] = [];
    for (const node of this.nodes.values()) {
      const range = node.ranges[name];
      if (range === undefined) continue;
      const resolved = this.resolve(node.path, name);
      if (!resolved || resolved.version !== version) continue;
      edges.push({
        dependent: node.path === "" ? "(root)" : `${node.name}@${node.version ?? "?"}`,
        range,
      });
    }
    return edges;
  }
}

/**
 * Build the dependency graph from a parsed package-lock.json. Returns null
 * for v1 locks, absent locks, or anything without a `packages` map — callers
 * pass null through to the resolution engine, which degrades honestly.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function buildDependencyGraph(packageLock: any): LockDependencyGraph | null {
  if (!packageLock || typeof packageLock !== "object") return null;
  if (!(packageLock.lockfileVersion >= 2) || !packageLock.packages) return null;
  return new LockDependencyGraph(packageLock.packages as Record<string, LockPackageEntry>);
}
