import { describe, it, expect, vi, afterEach } from "vitest";
import { sortBySeverity, scanProjectFiles } from "../src/scan";
import type { ScanVulnerability, Severity } from "../src/types";

function vuln(severity: Severity): ScanVulnerability {
  return {
    osvId: `id-${severity}`,
    cveId: null,
    package: "pkg",
    installedVersion: "1.0.0",
    fixedVersion: null,
    severity,
    cvssVector: null,
    cvssScore: null,
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
});
