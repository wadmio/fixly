import { describe, it, expect } from "vitest";
import type { ScanResult, ScanVulnerability } from "@fixly/core";
import { shouldVerify, verifyFindings } from "../src/verify";

function vuln(pkg: string, osvId: string): ScanVulnerability {
  return {
    osvId,
    cveId: null,
    package: pkg,
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
  };
}

function result(
  vulnerabilities: ScanVulnerability[],
  over: Partial<ScanResult> = {}
): ScanResult {
  return {
    repo: "demo",
    scannedAt: "2026-08-05T00:00:00Z",
    source: "osv",
    totalPackages: 3,
    directPackages: 3,
    transitivePackages: 0,
    resolvedPackages: 3,
    dependencies: [],
    vulnerabilities,
    target: {
      owner: null,
      repo: null,
      branch: null,
      subpath: null,
      filesFound: ["package.json", "package-lock.json"],
      filesMissing: [],
    },
    warnings: [],
    ...over,
  };
}

describe("verifyFindings — classification", () => {
  it("a disappeared finding is VERIFIED_RESOLVED", () => {
    const s = verifyFindings(
      result([vuln("minimist", "GHSA-a"), vuln("axios", "GHSA-b")]),
      result([vuln("axios", "GHSA-b")])
    );
    expect(s.resolved).toBe(1);
    expect(s.stillPresent).toBe(1);
    expect(s.introduced).toBe(0);
    expect(s.lines).toContain("VERIFIED_RESOLVED: minimist GHSA-a");
    expect(s.message).toBe(
      "Fixly verification: 1 resolved, 1 still present, 0 new findings introduced."
    );
  });

  it("an unchanged scan is all STILL_PRESENT", () => {
    const findings = [vuln("axios", "GHSA-b"), vuln("axios", "GHSA-c")];
    const s = verifyFindings(result(findings), result(findings));
    expect(s.resolved).toBe(0);
    expect(s.stillPresent).toBe(2);
    expect(s.introduced).toBe(0);
    expect(s.lines).toEqual([
      "STILL_PRESENT: axios GHSA-b",
      "STILL_PRESENT: axios GHSA-c",
    ]);
  });

  it("a new finding is NEW_FINDING_INTRODUCED and leads the detail lines", () => {
    const s = verifyFindings(
      result([vuln("axios", "GHSA-b")]),
      result([vuln("axios", "GHSA-b"), vuln("lodash", "GHSA-new")])
    );
    expect(s.introduced).toBe(1);
    expect(s.lines[0]).toBe("NEW_FINDING_INTRODUCED: lodash GHSA-new");
    expect(s.message).toContain("1 new finding introduced");
  });

  it("a mixed outcome counts all three classes", () => {
    const s = verifyFindings(
      result([vuln("minimist", "GHSA-a"), vuln("minimist", "GHSA-a2"), vuln("axios", "GHSA-b")]),
      result([vuln("axios", "GHSA-b"), vuln("lodash", "GHSA-new")])
    );
    expect(s.resolved).toBe(2);
    expect(s.stillPresent).toBe(1);
    expect(s.introduced).toBe(1);
    expect(s.message).toBe(
      "Fixly verification: 2 resolved, 1 still present, 1 new finding introduced."
    );
  });

  it("identity is package+advisory: a version bump that stays vulnerable is STILL_PRESENT", () => {
    const before = vuln("axios", "GHSA-b");
    const after = { ...vuln("axios", "GHSA-b"), installedVersion: "1.0.1" };
    const s = verifyFindings(result([before]), result([after]));
    expect(s.stillPresent).toBe(1);
    expect(s.resolved).toBe(0);
  });
});

describe("shouldVerify — when verification appears at all", () => {
  const prev = result([vuln("axios", "GHSA-b")]);
  const next = result([]);

  it("verifies only lock-triggered rescans with a previous scan", () => {
    expect(shouldVerify(true, prev, next)).toBe(true);
  });

  it("first scan: no previous scan, no verification", () => {
    expect(shouldVerify(true, undefined, next)).toBe(false);
  });

  it("non-lock rescans (manual, package.json save, on-type) never verify", () => {
    expect(shouldVerify(false, prev, next)).toBe(false);
    expect(shouldVerify(undefined, prev, next)).toBe(false);
  });

  it("an errored scan on either side blocks verification (a partial result must not fake resolutions)", () => {
    const errored = result([], {
      error: { code: "osv_failed", message: "OSV request failed" },
    });
    expect(shouldVerify(true, errored, next)).toBe(false);
    expect(shouldVerify(true, prev, errored)).toBe(false);
  });
});
