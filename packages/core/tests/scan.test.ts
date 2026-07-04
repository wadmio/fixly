import { describe, it, expect, vi, afterEach } from "vitest";
import { sortBySeverity, scanProjectFiles } from "../src/scan";
import type { ScanVulnerability, Severity } from "../src/types";

function vuln(severity: Severity, pkg = "pkg"): ScanVulnerability {
  return {
    osvId: `id-${severity}-${pkg}`,
    cveId: null,
    package: pkg,
    installedVersion: "1.0.0",
    fixedVersion: null,
    severity,
    cvssVector: null,
    cvssScore: null,
    affectedRanges: [],
    versionInRange: null,
    versionSource: "lockfile",
    dependencyType: "dependencies",
    sources: ["osv"],
    nvd: null,
    malicious: false,
    knownExploited: false,
    epssScore: null,
    epssPercentile: null,
    title: severity,
    description: "",
    references: [],
  };
}

function jsonRes(status: number, body: unknown) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

describe("sortBySeverity", () => {
  it("orders vulnerabilities critical → high → medium → low → unknown", () => {
    const sorted = sortBySeverity([
      vuln("low"),
      vuln("unknown"),
      vuln("critical"),
      vuln("medium"),
      vuln("high"),
    ]).map((v) => v.severity);
    expect(sorted).toEqual(["critical", "high", "medium", "low", "unknown"]);
  });

  it("breaks severity ties by package name", () => {
    const sorted = sortBySeverity([
      vuln("high", "zod"),
      vuln("high", "axios"),
      vuln("high", "lodash"),
    ]).map((v) => v.package);
    expect(sorted).toEqual(["axios", "lodash", "zod"]);
  });

  it("does not mutate the input array", () => {
    const input = [vuln("low"), vuln("critical")];
    const copy = [...input];
    sortBySeverity(input);
    expect(input).toEqual(copy);
  });
});

describe("scanProjectFiles", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns a no_dependencies error for an empty package.json", async () => {
    const r = await scanProjectFiles({ packageJson: {}, repo: "demo" });
    expect(r.error?.code).toBe("no_dependencies");
    expect(r.totalPackages).toBe(0);
    expect(r.vulnerabilities).toEqual([]);
  });

  it("produces a clean report when OSV finds nothing, with a no-lockfile warning", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("/querybatch")) return jsonRes(200, { results: [{}] });
        return jsonRes(200, {});
      })
    );
    const r = await scanProjectFiles({
      packageJson: { dependencies: { "left-pad": "1.3.0" } },
      packageLock: null,
      repo: "demo",
    });
    expect(r.error).toBeUndefined();
    expect(r.totalPackages).toBe(1);
    expect(r.resolvedPackages).toBe(1);
    expect(r.vulnerabilities).toEqual([]);
    expect(r.warnings.some((w) => w.includes("No package-lock.json"))).toBe(true);
  });

  it("scans transitive packages from the lock tree and tags findings by origin", async () => {
    // Direct: a@1.0.0 (clean). Transitive: b@2.0.0 (vulnerable, nested).
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: { body?: string }) => {
        if (url.includes("/querybatch")) {
          const body = JSON.parse(init?.body ?? "{}") as {
            queries: Array<{ package: { name: string } }>;
          };
          return jsonRes(200, {
            results: body.queries.map((q) =>
              q.package.name === "b" ? { vulns: [{ id: "GHSA-b" }] } : {}
            ),
          });
        }
        if (url.includes("/vulns/GHSA-b")) {
          return jsonRes(200, {
            id: "GHSA-b",
            summary: "b is vulnerable",
            database_specific: { severity: "HIGH" },
          });
        }
        return jsonRes(200, {});
      })
    );

    const r = await scanProjectFiles({
      packageJson: { dependencies: { a: "^1.0.0" } },
      packageLock: {
        lockfileVersion: 3,
        packages: {
          "": { name: "root" },
          "node_modules/a": { version: "1.0.0" },
          "node_modules/a/node_modules/b": { version: "2.0.0" },
        },
      },
      repo: "demo",
      nvd: false,
      intel: false,
    });

    expect(r.error).toBeUndefined();
    expect(r.directPackages).toBe(1);
    expect(r.transitivePackages).toBe(1);
    expect(r.totalPackages).toBe(2);
    expect(r.resolvedPackages).toBe(2);
    expect(r.vulnerabilities).toHaveLength(1);
    expect(r.vulnerabilities[0].package).toBe("b");
    expect(r.vulnerabilities[0].dependencyType).toBe("transitive");
    expect(r.vulnerabilities[0].sources).toEqual(["osv"]);
  });

  it("checks the same package at two versions without collisions", async () => {
    // lodash direct at 4.17.21 (clean) AND nested at 3.10.1 (vulnerable).
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: { body?: string }) => {
        if (url.includes("/querybatch")) {
          const body = JSON.parse(init?.body ?? "{}") as {
            queries: Array<{ package: { name: string }; version: string }>;
          };
          return jsonRes(200, {
            results: body.queries.map((q) =>
              q.version === "3.10.1" ? { vulns: [{ id: "GHSA-old" }] } : {}
            ),
          });
        }
        if (url.includes("/vulns/GHSA-old")) {
          return jsonRes(200, { id: "GHSA-old", summary: "old lodash" });
        }
        return jsonRes(200, {});
      })
    );

    const r = await scanProjectFiles({
      packageJson: { dependencies: { lodash: "^4.17.21" } },
      packageLock: {
        lockfileVersion: 3,
        packages: {
          "": { name: "root" },
          "node_modules/lodash": { version: "4.17.21" },
          "node_modules/x": { version: "1.0.0" },
          "node_modules/x/node_modules/lodash": { version: "3.10.1" },
        },
      },
      repo: "demo",
      nvd: false,
      intel: false,
    });

    expect(r.error).toBeUndefined();
    expect(r.vulnerabilities).toHaveLength(1);
    expect(r.vulnerabilities[0].package).toBe("lodash");
    expect(r.vulnerabilities[0].installedVersion).toBe("3.10.1");
    expect(r.vulnerabilities[0].dependencyType).toBe("transitive");
  });
});
