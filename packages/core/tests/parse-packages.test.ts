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

  it("resolves from a v2/v3 lockfile (packages map), ignoring nested deps", () => {
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
    expect(dependencies).toHaveLength(1);
    expect(dependencies[0].installedVersion).toBe("1.9.0");
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

describe("resolveCheckVersion", () => {
  it("prefers the lock version, falls back to the cleaned range, else null", () => {
    expect(resolveCheckVersion(entry({ installedVersion: "1.5.0" }))).toBe("1.5.0");
    expect(resolveCheckVersion(entry({ requestedVersion: "^1.2.3", installedVersion: null }))).toBe("1.2.3");
    expect(resolveCheckVersion(entry({ requestedVersion: "*", installedVersion: null }))).toBeNull();
  });
});
