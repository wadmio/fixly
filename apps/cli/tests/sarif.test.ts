import { describe, it, expect } from "vitest";
import { toSarif } from "../src/sarif";
import type { ScanResult, ScanVulnerability, Severity } from "@fixly/core";

function vuln(over: Partial<ScanVulnerability> & { severity: Severity }): ScanVulnerability {
  return {
    osvId: "GHSA-x",
    cveId: "CVE-2024-0001",
    package: "pkg",
    installedVersion: "1.0.0",
    fixedVersion: "2.0.0",
    cvssVector: null,
    cvssScore: null,
    affectedRanges: [],
    versionInRange: true,
    versionSource: "lockfile",
    dependencyType: "dependencies",
    sources: ["osv"],
    nvd: null,
    malicious: false,
    knownExploited: false,
    epssScore: null,
    epssPercentile: null,
    title: "Prototype pollution",
    description: "",
    references: ["https://example.com/advisory"],
    ...over,
  };
}

function result(vulnerabilities: ScanVulnerability[]): ScanResult {
  return {
    repo: "demo",
    target: { owner: null, repo: null, branch: null, subpath: null, filesFound: [], filesMissing: [] },
    scannedAt: "2026-07-03T00:00:00Z",
    source: "osv",
    dependencies: [],
    totalPackages: 1,
    directPackages: 1,
    transitivePackages: 0,
    resolvedPackages: 1,
    vulnerabilities,
    warnings: [],
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function firstRun(sarif: object): any {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (sarif as any).runs[0];
}

describe("toSarif", () => {
  it("produces a valid SARIF 2.1.0 skeleton with tool metadata", () => {
    const sarif = toSarif(result([]), "0.1.0");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((sarif as any).version).toBe("2.1.0");
    expect(firstRun(sarif).tool.driver.name).toBe("Fixly");
    expect(firstRun(sarif).results).toEqual([]);
  });

  it("maps severity to SARIF levels and escalates KEV/malicious to error", () => {
    const sarif = toSarif(
      result([
        vuln({ severity: "critical" }),
        vuln({ severity: "medium", osvId: "GHSA-m" }),
        vuln({ severity: "low", osvId: "GHSA-l" }),
        vuln({ severity: "low", osvId: "GHSA-kev", knownExploited: true }),
      ]),
      "0.1.0"
    );
    const levels = firstRun(sarif).results.map((r: { level: string }) => r.level);
    expect(levels).toEqual(["error", "warning", "note", "error"]);
  });

  it("dedupes rules by advisory id and points transitive findings at the lock file", () => {
    const sarif = toSarif(
      result([
        vuln({ severity: "high" }),
        vuln({ severity: "high", installedVersion: "1.1.0" }), // same GHSA-x
        vuln({ severity: "high", osvId: "GHSA-t", dependencyType: "transitive" }),
      ]),
      "0.1.0"
    );
    expect(firstRun(sarif).tool.driver.rules).toHaveLength(2);
    const uris = firstRun(sarif).results.map(
      (r: { locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }) =>
        r.locations[0].physicalLocation.artifactLocation.uri
    );
    expect(uris).toEqual(["package.json", "package.json", "package-lock.json"]);
  });

  it("includes the fix version in the message", () => {
    const sarif = toSarif(result([vuln({ severity: "high" })]), "0.1.0");
    expect(firstRun(sarif).results[0].message.text).toContain("upgrade to 2.0.0");
  });
});
