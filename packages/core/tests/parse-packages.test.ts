import { describe, it, expect } from "vitest";
import { parseDependencies, resolveCheckVersion } from "../src/parse-packages";
import type { DependencyEntry } from "../src/types";

const entry = (over: Partial<DependencyEntry>): DependencyEntry => ({
  name: "a",
  requestedVersion: "^1.2.3",
  installedVersion: null,
  dependencyType: "dependencies",
  sourceFile: "package.json",
  ...over,
});

describe("parseDependencies — extraction", () => {
  it("normalizes dependencies and devDependencies", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { a: "^1.2.3" }, devDependencies: { b: "~2.0.0" } },
      null
    );
    expect(dependencies).toContainEqual(
      entry({ name: "a", requestedVersion: "^1.2.3", dependencyType: "dependencies" })
    );
    expect(dependencies).toContainEqual(
      entry({ name: "b", requestedVersion: "~2.0.0", dependencyType: "devDependencies" })
    );
  });

  it("lets dependencies take precedence over devDependencies", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { a: "^1.0.0" }, devDependencies: { a: "^2.0.0" } },
      null
    );
    expect(dependencies.filter((d) => d.name === "a")).toHaveLength(1);
    expect(dependencies[0].dependencyType).toBe("dependencies");
  });
});

describe("parseDependencies — lockfile resolution", () => {
  it("resolves installedVersion from a v1 lockfile (dependencies map)", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { a: "^1.0.0" } },
      { dependencies: { a: { version: "1.5.0" } } }
    );
    expect(dependencies[0].installedVersion).toBe("1.5.0");
  });

  it("resolves the direct version from a v2/v3 lockfile, not a nested copy", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { a: "^1.0.0" } },
      {
        lockfileVersion: 3,
        packages: {
          "": { name: "root" },
          "node_modules/a": { version: "1.9.0" },
          "node_modules/a/node_modules/b": { version: "9.9.9" },
        },
      }
    );
    const direct = dependencies.find((d) => d.name === "a");
    expect(direct?.installedVersion).toBe("1.9.0");
    expect(direct?.dependencyType).toBe("dependencies");
    // The nested package is surfaced as a transitive entry (new default).
    const nested = dependencies.find((d) => d.name === "b");
    expect(nested?.dependencyType).toBe("transitive");
  });
});

describe("parseDependencies — warnings", () => {
  it("warns when no lockfile is provided", () => {
    const { warnings } = parseDependencies({ dependencies: { a: "1.0.0" } }, null);
    expect(
      warnings.some((w) => w.toLowerCase().includes("no package-lock.json"))
    ).toBe(true);
  });

  it("warns about and flags unresolvable version ranges", () => {
    const { dependencies, warnings } = parseDependencies(
      { dependencies: { x: "*", y: "latest" } },
      null
    );
    expect(dependencies.every((d) => resolveCheckVersion(d) === null)).toBe(true);
    const w = warnings.find((m) => m.includes("Could not determine a version"));
    expect(w).toContain("x");
    expect(w).toContain("y");
  });
});

describe("parseDependencies — transitive discovery", () => {
  const lockV3 = {
    lockfileVersion: 3,
    packages: {
      "": { name: "root" },
      "node_modules/a": { version: "1.0.0" },
      "node_modules/b": { version: "2.0.0" },
      "node_modules/@scope/c": { version: "3.0.0" },
      "node_modules/a/node_modules/b": { version: "1.5.0" },
      "node_modules/linked": { link: true },
    },
  };

  it("discovers transitive packages from a v2/v3 lock tree, including nested copies", () => {
    const { dependencies } = parseDependencies({ dependencies: { a: "^1.0.0" } }, lockV3);
    const transitive = dependencies.filter((d) => d.dependencyType === "transitive");
    expect(transitive.map((d) => `${d.name}@${d.installedVersion}`).sort()).toEqual([
      "@scope/c@3.0.0",
      "b@1.5.0",
      "b@2.0.0",
    ]);
    // Direct entry is not duplicated as transitive; links are skipped.
    expect(dependencies.filter((d) => d.name === "a")).toHaveLength(1);
    expect(dependencies.some((d) => d.name === "linked")).toBe(false);
    // Transitive entries carry exact versions from the lock file.
    for (const d of transitive) {
      expect(d.installedVersion).not.toBeNull();
      expect(d.sourceFile).toBe("package-lock.json");
    }
  });

  it("keeps a nested different-version copy of a direct package as transitive", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { b: "^2.0.0" } },
      lockV3
    );
    const bs = dependencies.filter((d) => d.name === "b");
    expect(bs).toHaveLength(2);
    expect(bs.find((d) => d.dependencyType === "dependencies")?.installedVersion).toBe("2.0.0");
    expect(bs.find((d) => d.dependencyType === "transitive")?.installedVersion).toBe("1.5.0");
  });

  it("walks nested v1 lock dependencies recursively", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { a: "^1.0.0" } },
      {
        dependencies: {
          a: { version: "1.0.0", dependencies: { deep: { version: "0.5.0" } } },
        },
      }
    );
    const deep = dependencies.find((d) => d.name === "deep");
    expect(deep?.dependencyType).toBe("transitive");
    expect(deep?.installedVersion).toBe("0.5.0");
  });

  it("can be disabled via includeTransitive: false", () => {
    const { dependencies } = parseDependencies(
      { dependencies: { a: "^1.0.0" } },
      lockV3,
      { includeTransitive: false }
    );
    expect(dependencies.every((d) => d.dependencyType !== "transitive")).toBe(true);
  });

  it("notes that transitive discovery needs a lock file when none is present", () => {
    const { warnings } = parseDependencies({ dependencies: { a: "1.0.0" } }, null);
    expect(warnings.some((w) => w.includes("Transitive dependencies cannot be discovered"))).toBe(
      true
    );
  });
});

describe("resolveCheckVersion", () => {
  it("prefers the lock version, falls back to the cleaned range, else null", () => {
    expect(resolveCheckVersion(entry({ installedVersion: "1.5.0" }))).toBe("1.5.0");
    expect(resolveCheckVersion(entry({ requestedVersion: "^1.2.3", installedVersion: null }))).toBe("1.2.3");
    expect(resolveCheckVersion(entry({ requestedVersion: "*", installedVersion: null }))).toBeNull();
  });
});
