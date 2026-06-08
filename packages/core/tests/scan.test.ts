import { describe, it, expect } from "vitest";
import { sortBySeverity } from "../src/scan";
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

describe("sortBySeverity", () => {
  it("orders vulnerabilities critical → high → medium → low → unknown", () => {
    const input = [
      vuln("low"),
      vuln("unknown"),
      vuln("critical"),
      vuln("medium"),
      vuln("high"),
    ];
    const sorted = sortBySeverity(input).map((v) => v.severity);
    expect(sorted).toEqual(["critical", "high", "medium", "low", "unknown"]);
  });

  it("does not mutate the input array", () => {
    const input = [vuln("low"), vuln("critical")];
    const copy = [...input];
    sortBySeverity(input);
    expect(input).toEqual(copy);
  });
});
