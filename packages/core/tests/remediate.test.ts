import { describe, it, expect } from "vitest";
import { buildRemediationPlan } from "../src/remediate";
import { buildDependencyGraph } from "../src/lock-graph";
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
    kevDateAdded: null,
    pocCount: null,
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
    scannedAt: "2026-07-09T00:00:00Z",
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

describe("buildRemediationPlan", () => {
  it("a clean scan yields an empty plan with a flat forecast", () => {
    const plan = buildRemediationPlan(result([]));
    expect(plan.actions).toEqual([]);
    expect(plan.unfixable).toEqual([]);
    expect(plan.forecast.before).toEqual(plan.forecast.after);
    expect(plan.forecast.pointsRecovered).toBe(0);
  });

  it("direct deps upgrade, transitive deps override, malware is removed — in that priority order", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({ severity: "high", package: "direct-pkg" }),
        vuln({
          severity: "critical",
          package: "deep-pkg",
          dependencyType: "transitive",
          knownExploited: true,
        }),
        vuln({ severity: "low", package: "evil-pkg", malicious: true, osvId: "MAL-1" }),
      ])
    );
    expect(plan.actions.map((a) => a.kind)).toEqual(["remove", "override", "upgrade"]);
    expect(plan.actions[0].command).toBe("npm uninstall evil-pkg");
    expect(plan.actions[1].command).toBe("npm pkg set overrides.deep-pkg=2.0.0 && npm install");
    expect(plan.actions[2].command).toBe("npm install direct-pkg@2.0.0");
  });

  it("a transitive malware advisory with a fix is pinned via overrides, not left to manual removal", () => {
    // fsevents <1.2.11 (MAL-2023-462) is a legit package caught in a past
    // incident with a published fix — you can't uninstall a transitive dep, so
    // the actionable remediation is an override to the fixed version.
    const plan = buildRemediationPlan(
      result([
        vuln({
          severity: "critical",
          package: "fsevents",
          dependencyType: "transitive",
          malicious: true,
          osvId: "MAL-2023-462",
          fixedVersion: "1.2.11",
        }),
      ])
    );
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].kind).toBe("override");
    expect(plan.actions[0].targetVersion).toBe("1.2.11");
    expect(plan.actions[0].command).toBe(
      "npm pkg set overrides.fsevents=1.2.11 && npm install"
    );
    expect(plan.unfixable).toEqual([]);
  });

  it("a transitive malware advisory with NO fix still requires manual removal", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({
          severity: "critical",
          package: "evil-transitive",
          dependencyType: "transitive",
          malicious: true,
          osvId: "MAL-9",
          fixedVersion: null,
        }),
      ])
    );
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].kind).toBe("remove");
  });

  it("a DIRECT malware advisory is removed even when it has a fix", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({
          severity: "low",
          package: "evil-direct",
          malicious: true,
          osvId: "MAL-7",
          fixedVersion: "2.0.0",
        }),
      ])
    );
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].kind).toBe("remove");
    expect(plan.actions[0].command).toBe("npm uninstall evil-direct");
  });

  it("one bump per package clears every finding at the highest fixed version", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({ severity: "high", package: "multi", osvId: "GHSA-a", fixedVersion: "1.5.0" }),
        vuln({ severity: "medium", package: "multi", osvId: "GHSA-b", fixedVersion: "1.9.2" }),
      ])
    );
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].targetVersion).toBe("1.9.2");
    expect(plan.actions[0].resolves).toEqual(["GHSA-a", "GHSA-b"]);
  });

  it("findings without a fixed release land in unfixable and cap the forecast", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({ severity: "critical", package: "fixable" }),
        vuln({ severity: "high", package: "stuck", osvId: "GHSA-stuck", fixedVersion: null }),
      ])
    );
    expect(plan.actions).toHaveLength(1);
    expect(plan.unfixable).toEqual([
      { package: "stuck", installedVersion: "1.0.0", osvId: "GHSA-stuck", severity: "high" },
    ]);
    expect(plan.fixableFindings).toBe(1);
    // The unfixable high still costs points after remediation.
    expect(plan.forecast.after.score).toBeLessThan(100);
    expect(plan.forecast.after.score).toBeGreaterThan(plan.forecast.before.score);
  });

  it("the forecast is real grade arithmetic: after equals grading the residual scan", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({ severity: "critical", package: "a", knownExploited: true }),
        vuln({ severity: "high", package: "b" }),
      ])
    );
    expect(plan.forecast.after.grade).toBe("A");
    expect(plan.forecast.after.score).toBe(100);
    expect(plan.forecast.pointsRecovered).toBeCloseTo(
      plan.forecast.after.score - plan.forecast.before.score
    );
  });

  it("is deterministic", () => {
    const vulns = [
      vuln({ severity: "critical", package: "a" }),
      vuln({ severity: "high", package: "b", dependencyType: "transitive" }),
    ];
    expect(buildRemediationPlan(result(vulns))).toEqual(buildRemediationPlan(result(vulns)));
  });
});

describe("buildRemediationPlan with a dependency graph", () => {
  // parent@3.0.0 pins the vulnerable transitive dep to ~1.0.0; the fix is 1.1.0.
  const blockingLock = {
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { parent: "^3.0.0" } },
      "node_modules/parent": { version: "3.0.0", dependencies: { pinned: "~1.0.0" } },
      "node_modules/pinned": { version: "1.0.0" },
    },
  };

  it("a blocked transitive fix moves to plan.blocked (advice-only) and caps the forecast", () => {
    const graph = buildDependencyGraph(blockingLock)!;
    const scan = result([
      vuln({
        severity: "high",
        package: "pinned",
        dependencyType: "transitive",
        osvId: "GHSA-blocked",
        fixedVersion: "1.1.0",
      }),
    ]);
    const plan = buildRemediationPlan(scan, { graph });

    expect(plan.actions).toEqual([]);
    expect(plan.unfixable).toEqual([]);
    expect(plan.blocked).toHaveLength(1);
    expect(plan.blocked[0].path).toBe("BLOCKED_BY_PARENT");
    expect(plan.blocked[0].blockers).toEqual([
      { dependent: "parent@3.0.0", range: "~1.0.0" },
    ]);
    expect(plan.fixableFindings).toBe(0);
    // The blocked finding still costs points in the forecast — we never
    // forecast a fix we don't offer.
    expect(plan.forecast.after.score).toBe(plan.forecast.before.score);
  });

  it("blocked MALWARE falls back to a manual remove action, never advice-only", () => {
    const graph = buildDependencyGraph(blockingLock)!;
    const scan = result([
      vuln({
        severity: "critical",
        package: "pinned",
        dependencyType: "transitive",
        osvId: "MAL-77",
        malicious: true,
        fixedVersion: "1.1.0",
      }),
    ]);
    const plan = buildRemediationPlan(scan, { graph });

    expect(plan.blocked).toEqual([]);
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].kind).toBe("remove");
    expect(plan.actions[0].command).toContain("npm ls pinned");
  });

  it("an unblocked transitive fix keeps its override action, now carrying the resolution", () => {
    const permissiveLock = {
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { parent: "^3.0.0" } },
        "node_modules/parent": { version: "3.0.0", dependencies: { loose: "^1.0.0" } },
        "node_modules/loose": { version: "1.0.0" },
      },
    };
    const graph = buildDependencyGraph(permissiveLock)!;
    const plan = buildRemediationPlan(
      result([
        vuln({
          severity: "high",
          package: "loose",
          dependencyType: "transitive",
          osvId: "GHSA-loose",
          fixedVersion: "1.1.0",
        }),
      ]),
      { graph }
    );

    expect(plan.actions).toHaveLength(1);
    expect(plan.actions[0].kind).toBe("override");
    expect(plan.actions[0].targetVersion).toBe("1.1.0");
    expect(plan.actions[0].resolution?.path).toBe("TRANSITIVE_OVERRIDE");
    expect(plan.actions[0].resolution?.risk).toBe("elevated");
    expect(plan.actions[0].resolution?.constraintsChecked).toBe(true);
    expect(plan.blocked).toEqual([]);
  });

  it("upgrade actions carry DIRECT resolutions with distance and risk", () => {
    const plan = buildRemediationPlan(
      result([vuln({ severity: "high", package: "direct-pkg", fixedVersion: "1.0.5" })])
    );
    expect(plan.actions[0].resolution?.path).toBe("DIRECT");
    expect(plan.actions[0].resolution?.semverDistance).toBe("PATCH");
    expect(plan.actions[0].resolution?.risk).toBe("low");
    expect(plan.actions[0].resolution?.constraintsChecked).toBe(false);
  });
});
