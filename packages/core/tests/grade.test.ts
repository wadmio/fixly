import { describe, it, expect } from "vitest";
import { computeGrade } from "../src/grade";
import type { ScanResult, ScanVulnerability, Severity } from "../src/types";

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
    title: "t",
    description: "",
    references: [],
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
    totalPackages: 10,
    directPackages: 10,
    transitivePackages: 0,
    resolvedPackages: 10,
    vulnerabilities,
    warnings: [],
  };
}

describe("computeGrade", () => {
  it("grades a clean scan A with a shippable headline", () => {
    const g = computeGrade(result([]));
    expect(g.grade).toBe("A");
    expect(g.score).toBe(100);
    expect(g.topFixes).toEqual([]);
    expect(g.headline).toContain("Ship it");
  });

  it("a malicious package is an automatic F with an uninstall fix", () => {
    const g = computeGrade(result([vuln({ severity: "critical", malicious: true, osvId: "MAL-1" })]));
    expect(g.grade).toBe("F");
    expect(g.headline).toContain("malicious");
    expect(g.topFixes[0].command).toBe("npm uninstall pkg");
  });

  it("KEV findings are penalized far above their base severity", () => {
    const plain = computeGrade(result([vuln({ severity: "high" })]));
    const kev = computeGrade(result([vuln({ severity: "high", knownExploited: true })]));
    expect(kev.score).toBeLessThan(plain.score - 20);
    expect(kev.breakdown[0].reason).toContain("exploited in the wild");
  });

  it("top fixes rank by recoverable points and emit copy-paste commands", () => {
    const g = computeGrade(
      result([
        vuln({ severity: "low", package: "minor-pkg" }),
        vuln({ severity: "critical", package: "urgent-pkg", knownExploited: true }),
        vuln({ severity: "medium", package: "meh-pkg" }),
      ])
    );
    expect(g.topFixes[0].package).toBe("urgent-pkg");
    expect(g.topFixes[0].command).toBe("npm install urgent-pkg@2.0.0");
  });

  it("transitive fixes point at overrides instead of a direct install", () => {
    const g = computeGrade(
      result([vuln({ severity: "high", package: "deep-pkg", dependencyType: "transitive" })])
    );
    expect(g.topFixes[0].command).toContain("overrides");
  });

  it("many criticals sink the grade to F, deterministically", () => {
    const vulns = Array.from({ length: 5 }, (_, i) =>
      vuln({ severity: "critical", package: `p${i}` })
    );
    const g1 = computeGrade(result(vulns));
    const g2 = computeGrade(result(vulns));
    expect(g1.grade).toBe("F");
    expect(g1).toEqual(g2);
  });
});
