import { describe, it, expect } from "vitest";
import type { PackageVerdict, ScanVulnerability } from "@fixly/core";
import { compactVerdict } from "../src/responses";

function vuln(over: Partial<ScanVulnerability> = {}): ScanVulnerability {
  return {
    osvId: "GHSA-xxxx",
    cveId: null,
    package: "left-pad",
    installedVersion: "1.0.0",
    fixedVersion: "1.0.5",
    severity: "high",
    cvssVector: null,
    cvssScore: 7.5,
    affectedRanges: ["<1.0.5"],
    versionInRange: true,
    versionSource: "lockfile",
    dependencyType: "dependencies",
    sources: ["osv"],
    nvd: null,
    malicious: false,
    knownExploited: false,
    epssScore: null,
    epssPercentile: null,
    kevDateAdded: null,
    pocCount: null,
    title: "A vulnerability",
    description: "",
    references: [],
    ...over,
  };
}

function verdict(vulnerabilities: ScanVulnerability[]): PackageVerdict {
  return {
    package: "left-pad",
    version: "1.0.0",
    evaluatedVersion: "1.0.0",
    verdict: "caution",
    reasons: ["known vulnerabilities"],
    summary: "caution",
    signals: {
      exists: true,
      versionExists: true,
      popular: false,
      ageDays: 1000,
      lastPublishDays: 10,
      weeklyDownloads: 1000,
      deprecated: false,
      hasInstallScripts: false,
      maintainers: 1,
      typosquatOf: null,
      nameRiskScore: null,
      nameRiskFlagged: false,
      maliciousIds: [],
      vulnerabilityCounts: { critical: 0, high: vulnerabilities.length, medium: 0, low: 0, unknown: 0 },
      knownExploitedCves: [],
      maxEpss: null,
    },
    vulnerabilities,
    warnings: [],
  };
}

describe("compactVerdict fixCommand", () => {
  it("recommends the HIGHEST fixed version, not the first advisory's fix", () => {
    // OSV order deliberately lists the lower fix first — installing 1.0.2
    // would leave GHSA-b open. The agent must be told 1.2.6.
    const v = verdict([
      vuln({ osvId: "GHSA-a", fixedVersion: "1.0.2" }),
      vuln({ osvId: "GHSA-b", fixedVersion: "1.2.6" }),
      vuln({ osvId: "GHSA-c", fixedVersion: null }),
    ]);
    expect(compactVerdict(v).fixCommand).toBe("npm install left-pad@1.2.6");
  });

  it("is order-independent", () => {
    const v = verdict([
      vuln({ osvId: "GHSA-b", fixedVersion: "1.2.6" }),
      vuln({ osvId: "GHSA-a", fixedVersion: "1.0.2" }),
    ]);
    expect(compactVerdict(v).fixCommand).toBe("npm install left-pad@1.2.6");
  });

  it("returns no command when nothing has a published fix", () => {
    const v = verdict([vuln({ fixedVersion: null })]);
    expect(compactVerdict(v).fixCommand).toBeNull();
  });
});
