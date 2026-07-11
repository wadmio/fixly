import { describe, it, expect } from "vitest";
import { buildRemediationPlan, applyRemediationPlan } from "../src/remediate";
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

describe("applyRemediationPlan", () => {
  const manifest = JSON.stringify(
    {
      name: "demo",
      dependencies: { "direct-pkg": "^1.0.0", "evil-pkg": "1.0.0" },
      devDependencies: { "tilde-pkg": "~1.0.0" },
    },
    null,
    2
  ) + "\n";

  it("bumps direct deps preserving range style, removes malware, pins transitives via overrides", () => {
    const plan = buildRemediationPlan(
      result([
        vuln({ severity: "high", package: "direct-pkg" }),
        vuln({ severity: "medium", package: "tilde-pkg", fixedVersion: "1.4.0" }),
        vuln({ severity: "low", package: "evil-pkg", malicious: true, osvId: "MAL-1" }),
        vuln({ severity: "critical", package: "deep-pkg", dependencyType: "transitive" }),
      ])
    );
    const applied = applyRemediationPlan(manifest, plan);
    const out = JSON.parse(applied.text);
    expect(out.dependencies["direct-pkg"]).toBe("^2.0.0");
    expect(out.devDependencies["tilde-pkg"]).toBe("~1.4.0");
    expect(out.dependencies["evil-pkg"]).toBeUndefined();
    expect(out.overrides["deep-pkg"]).toBe("2.0.0");
    expect(applied.skipped).toEqual([]);
    expect(applied.changes).toHaveLength(4);
    expect(applied.text.endsWith("\n")).toBe(true);
  });

  it("skips upgrades for packages not declared in the manifest instead of inventing entries", () => {
    const plan = buildRemediationPlan(result([vuln({ severity: "high", package: "ghost-pkg" })]));
    const applied = applyRemediationPlan(manifest, plan);
    expect(applied.skipped).toHaveLength(1);
    expect(applied.skipped[0].package).toBe("ghost-pkg");
    expect(JSON.parse(applied.text)).toEqual(JSON.parse(manifest));
  });

  it("preserves the manifest's indentation", () => {
    const fourSpace = JSON.stringify({ dependencies: { "direct-pkg": "1.0.0" } }, null, 4);
    const plan = buildRemediationPlan(result([vuln({ severity: "high", package: "direct-pkg" })]));
    const applied = applyRemediationPlan(fourSpace, plan);
    expect(applied.text).toContain('\n    "dependencies"');
    expect(JSON.parse(applied.text).dependencies["direct-pkg"]).toBe("2.0.0");
  });
});
