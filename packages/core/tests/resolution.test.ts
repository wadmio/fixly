import { describe, it, expect } from "vitest";
import {
  resolveRemediation,
  semverDistanceBetween,
  type DependencyGraph,
} from "../src/resolution";
import type { ScanVulnerability, Severity } from "../src/types";

function vuln(over: Partial<ScanVulnerability> & { severity: Severity }): ScanVulnerability {
  return {
    osvId: "GHSA-x",
    cveId: "CVE-2024-0001",
    package: "pkg",
    installedVersion: "1.0.0",
    fixedVersion: "1.0.1",
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
    kevDateAdded: null,
    pocCount: null,
    title: "t",
    description: "",
    references: [],
    ...over,
  };
}

/** A stub graph: dependents keyed by "name@version". */
function graphOf(edges: Record<string, Array<{ dependent: string; range: string }>>): DependencyGraph {
  return {
    dependentsOf: (name, version) => edges[`${name}@${version}`] ?? [],
  };
}

describe("semverDistanceBetween", () => {
  it("classifies patch, minor, and major jumps", () => {
    expect(semverDistanceBetween("1.2.3", "1.2.4")).toBe("PATCH");
    expect(semverDistanceBetween("1.2.3", "1.4.0")).toBe("MINOR");
    expect(semverDistanceBetween("1.2.3", "2.0.0")).toBe("MAJOR");
  });

  it("returns null when either side is unparseable", () => {
    expect(semverDistanceBetween("latest", "1.0.0")).toBeNull();
    expect(semverDistanceBetween("1.0.0", "unknown")).toBeNull();
  });
});

describe("resolveRemediation — direct dependencies", () => {
  it("a patch-level direct fix is DIRECT with low risk", () => {
    const r = resolveRemediation([vuln({ severity: "high" })]);
    expect(r.path).toBe("DIRECT");
    expect(r.targetVersion).toBe("1.0.1");
    expect(r.semverDistance).toBe("PATCH");
    expect(r.risk).toBe("low");
    expect(r.resolves).toEqual(["GHSA-x"]);
    expect(r.constraintsChecked).toBe(false);
    expect(r.rationale).toContain("1.0.1");
    expect(r.rationale).toContain("patch-level bump");
    expect(r.rationale).toContain("not checked");
  });

  it("a MAJOR jump is elevated risk and says so", () => {
    const r = resolveRemediation([vuln({ severity: "high", fixedVersion: "2.0.0" })]);
    expect(r.semverDistance).toBe("MAJOR");
    expect(r.risk).toBe("elevated");
    expect(r.rationale).toContain("breaking changes");
  });

  it("an unmeasurable jump is treated as elevated, not low", () => {
    const r = resolveRemediation([
      vuln({ severity: "high", installedVersion: "weird", fixedVersion: "2.0.0" }),
    ]);
    expect(r.semverDistance).toBeNull();
    expect(r.risk).toBe("elevated");
    expect(r.rationale).toContain("could not be determined");
  });

  it("picks the minimum version clearing every advisory (max of per-advisory minimal fixes)", () => {
    const r = resolveRemediation([
      vuln({ severity: "high", osvId: "GHSA-a", fixedVersion: "1.5.0" }),
      vuln({ severity: "medium", osvId: "GHSA-b", fixedVersion: "1.9.2" }),
    ]);
    expect(r.targetVersion).toBe("1.9.2");
    expect(r.resolves).toEqual(["GHSA-a", "GHSA-b"]);
    expect(r.rationale).toContain("GHSA-a");
    expect(r.rationale).toContain("GHSA-b");
  });

  it("notes when the candidate may still sit in another advisory's affected range", () => {
    const r = resolveRemediation([
      vuln({ severity: "high", osvId: "GHSA-a", fixedVersion: "1.2.0" }),
      vuln({
        severity: "medium",
        osvId: "GHSA-b",
        fixedVersion: "1.1.0",
        affectedRanges: [">=1.0.5 <1.1.0", ">=1.1.5 <1.3.0"],
      }),
    ]);
    expect(r.targetVersion).toBe("1.2.0"); // max of minimal fixes
    expect(r.rationale).toContain("GHSA-b may still affect 1.2.0");
  });

  it("NO_FIX_AVAILABLE is a terminal state with no target and no risk", () => {
    const r = resolveRemediation([
      vuln({ severity: "critical", osvId: "GHSA-stuck", fixedVersion: null }),
    ]);
    expect(r.path).toBe("NO_FIX_AVAILABLE");
    expect(r.targetVersion).toBeNull();
    expect(r.semverDistance).toBeNull();
    expect(r.risk).toBeNull();
    expect(r.resolves).toEqual([]);
    expect(r.rationale).toContain("GHSA-stuck");
    expect(r.rationale).toContain("no fixed release");
  });
});

describe("resolveRemediation — transitive dependencies", () => {
  it("a transitive fix is TRANSITIVE_OVERRIDE with elevated risk even for a patch jump", () => {
    const r = resolveRemediation([
      vuln({ severity: "high", dependencyType: "transitive" }),
    ]);
    expect(r.path).toBe("TRANSITIVE_OVERRIDE");
    expect(r.targetVersion).toBe("1.0.1");
    expect(r.semverDistance).toBe("PATCH");
    expect(r.risk).toBe("elevated");
    expect(r.rationale).toContain("overrides");
    expect(r.rationale).toContain("not declared in package.json");
  });
});

describe("resolveRemediation — dependent constraints (stub graph)", () => {
  it("a dependent range that permits the fix keeps the path and records the check", () => {
    const graph = graphOf({
      "pkg@1.0.0": [{ dependent: "parent@3.0.0", range: "^1.0.0" }],
    });
    const r = resolveRemediation([vuln({ severity: "high", dependencyType: "transitive" })], graph);
    expect(r.path).toBe("TRANSITIVE_OVERRIDE");
    expect(r.constraintsChecked).toBe(true);
    expect(r.blockers).toEqual([]);
    expect(r.rationale).toContain("checked against the lock-file graph");
  });

  it("a dependent range that forbids the fix yields BLOCKED_BY_PARENT (advice-only)", () => {
    const graph = graphOf({
      "pkg@1.0.0": [{ dependent: "parent@3.0.0", range: "~1.0.0" }],
    });
    const r = resolveRemediation(
      [vuln({ severity: "high", dependencyType: "transitive", fixedVersion: "1.1.0" })],
      graph
    );
    expect(r.path).toBe("BLOCKED_BY_PARENT");
    expect(r.targetVersion).toBeNull();
    expect(r.risk).toBeNull();
    expect(r.resolves).toEqual([]);
    expect(r.blockers).toEqual([{ dependent: "parent@3.0.0", range: "~1.0.0" }]);
    expect(r.rationale).toContain("1.1.0");
    expect(r.rationale).toContain('parent@3.0.0 requires "~1.0.0"');
    expect(r.rationale).toContain("No edit offered");
  });

  it("the root manifest's own range never blocks a direct upgrade", () => {
    const graph = graphOf({
      "pkg@1.0.0": [{ dependent: "(root)", range: "~1.0.0" }],
    });
    const r = resolveRemediation([vuln({ severity: "high", fixedVersion: "2.0.0" })], graph);
    expect(r.path).toBe("DIRECT");
    expect(r.targetVersion).toBe("2.0.0");
  });

  it("an unevaluable dependent range is noted but never blocks", () => {
    const graph = graphOf({
      "pkg@1.0.0": [{ dependent: "parent@1.0.0", range: "workspace:*" }],
    });
    const r = resolveRemediation([vuln({ severity: "high" })], graph);
    expect(r.path).toBe("DIRECT");
    expect(r.blockers).toEqual([]);
    expect(r.rationale).toContain("could not evaluate");
    expect(r.rationale).toContain("parent@1.0.0");
    expect(r.rationale).toContain("not as blocking");
  });

  it("is deterministic", () => {
    const findings = [
      vuln({ severity: "high", osvId: "GHSA-a", fixedVersion: "1.5.0" }),
      vuln({ severity: "medium", osvId: "GHSA-b", fixedVersion: "1.9.2" }),
    ];
    expect(resolveRemediation(findings)).toEqual(resolveRemediation(findings));
  });
});
