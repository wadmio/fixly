import { describe, it, expect } from "vitest";
import { buildDependencyGraph } from "../src/lock-graph";

// A v3 lock shaped like a real npm tree:
//   root -> a@1.0.0 (^1.0.0), react@17.0.2 (^17.0.0), dev-tool@2.0.0 (dev)
//   a -> b@2.0.0 (^2.0.0), c (^2.0.0 — resolves to its NESTED copy c@2.5.0)
//   b -> c (^3.0.0 — resolves to the TOP-LEVEL c@3.0.0)
//   p@1.0.0 -> peerDependencies react ^17.0.0
//   linked-pkg is a workspace symlink (link: true) and must be ignored.
const lock = {
  lockfileVersion: 3,
  packages: {
    "": {
      name: "demo",
      dependencies: { a: "^1.0.0", react: "^17.0.0", p: "^1.0.0" },
      devDependencies: { "dev-tool": "^2.0.0" },
    },
    "node_modules/a": {
      version: "1.0.0",
      dependencies: { b: "^2.0.0", c: "^2.0.0" },
    },
    "node_modules/b": {
      version: "2.0.0",
      dependencies: { c: "^3.0.0" },
    },
    "node_modules/c": { version: "3.0.0" },
    "node_modules/a/node_modules/c": { version: "2.5.0" },
    "node_modules/react": { version: "17.0.2" },
    "node_modules/p": {
      version: "1.0.0",
      peerDependencies: { react: "^17.0.0" },
    },
    "node_modules/dev-tool": { version: "2.0.0" },
    "node_modules/linked-pkg": { version: "9.9.9", link: true },
  },
};

describe("buildDependencyGraph", () => {
  it("returns null for v1 locks, absent locks, and lock files without packages", () => {
    expect(buildDependencyGraph(null)).toBeNull();
    expect(buildDependencyGraph(undefined)).toBeNull();
    expect(buildDependencyGraph({ lockfileVersion: 1, dependencies: {} })).toBeNull();
    expect(buildDependencyGraph({ lockfileVersion: 3 })).toBeNull();
  });

  it("the root manifest is a dependent labeled (root), for dev deps too", () => {
    const graph = buildDependencyGraph(lock)!;
    expect(graph.dependentsOf("a", "1.0.0")).toEqual([
      { dependent: "(root)", range: "^1.0.0" },
    ]);
    expect(graph.dependentsOf("dev-tool", "2.0.0")).toEqual([
      { dependent: "(root)", range: "^2.0.0" },
    ]);
  });

  it("finds transitive dependents with their declared ranges", () => {
    const graph = buildDependencyGraph(lock)!;
    expect(graph.dependentsOf("b", "2.0.0")).toEqual([
      { dependent: "a@1.0.0", range: "^2.0.0" },
    ]);
  });

  it("nearest-node_modules resolution: nested copies get their true dependents", () => {
    const graph = buildDependencyGraph(lock)!;
    // a resolves c to its nested 2.5.0 copy; b resolves c to the hoisted 3.0.0.
    expect(graph.dependentsOf("c", "2.5.0")).toEqual([
      { dependent: "a@1.0.0", range: "^2.0.0" },
    ]);
    expect(graph.dependentsOf("c", "3.0.0")).toEqual([
      { dependent: "b@2.0.0", range: "^3.0.0" },
    ]);
  });

  it("peerDependencies count as dependent constraints", () => {
    const graph = buildDependencyGraph(lock)!;
    const reactDeps = graph.dependentsOf("react", "17.0.2");
    expect(reactDeps).toContainEqual({ dependent: "p@1.0.0", range: "^17.0.0" });
    expect(reactDeps).toContainEqual({ dependent: "(root)", range: "^17.0.0" });
  });

  it("workspace links are ignored and unknown packages have no dependents", () => {
    const graph = buildDependencyGraph(lock)!;
    expect(graph.dependentsOf("linked-pkg", "9.9.9")).toEqual([]);
    expect(graph.dependentsOf("ghost", "1.0.0")).toEqual([]);
    // A version that nothing resolves to has no dependents either.
    expect(graph.dependentsOf("c", "9.9.9")).toEqual([]);
  });

  it("works for lockfileVersion 2 as well", () => {
    const graph = buildDependencyGraph({ ...lock, lockfileVersion: 2 })!;
    expect(graph.dependentsOf("b", "2.0.0")).toEqual([
      { dependent: "a@1.0.0", range: "^2.0.0" },
    ]);
  });
});
