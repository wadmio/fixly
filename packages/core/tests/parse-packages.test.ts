import { describe, it, expect } from "vitest";
import { parsePackages } from "../src/parse-packages";

describe("parsePackages — dependency extraction", () => {
  it("extracts dependencies and devDependencies, marking dev correctly", () => {
    const { packages } = parsePackages(
      {
        dependencies: { a: "^1.2.3" },
        devDependencies: { b: "~2.0.0" },
      },
      null
    );
    expect(packages).toContainEqual({ name: "a", version: "1.2.3", isDev: false });
    expect(packages).toContainEqual({ name: "b", version: "2.0.0", isDev: true });
  });
});

describe("parsePackages — lockfile version resolution", () => {
  it("resolves versions from a v1 lockfile (dependencies map)", () => {
    const { packages } = parsePackages(
      { dependencies: { a: "^1.0.0" } },
      { dependencies: { a: { version: "1.5.0" } } }
    );
    expect(packages).toEqual([{ name: "a", version: "1.5.0", isDev: false }]);
  });

  it("resolves versions from a v2/v3 lockfile (packages map), ignoring nested deps", () => {
    const { packages } = parsePackages(
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
    expect(packages).toEqual([{ name: "a", version: "1.9.0", isDev: false }]);
  });

  it("prefers the lockfile version over the package.json range", () => {
    const { packages } = parsePackages(
      { dependencies: { a: "^1.0.0" } },
      {
        lockfileVersion: 2,
        packages: { "node_modules/a": { version: "1.4.2" } },
      }
    );
    expect(packages[0].version).toBe("1.4.2");
  });
});

describe("parsePackages — warnings", () => {
  it("warns when no lockfile is provided", () => {
    const { warnings } = parsePackages({ dependencies: { a: "1.0.0" } }, null);
    expect(warnings.some((w) => w.toLowerCase().includes("no package-lock.json"))).toBe(
      true
    );
  });

  it("warns about and skips unresolvable version ranges", () => {
    const { packages, warnings } = parsePackages(
      { dependencies: { x: "*", y: "latest" } },
      null
    );
    expect(packages).toEqual([]);
    const unresolved = warnings.find((w) => w.includes("Could not resolve"));
    expect(unresolved).toContain("x");
    expect(unresolved).toContain("y");
  });
});
