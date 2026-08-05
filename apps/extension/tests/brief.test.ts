import { describe, it, expect } from "vitest";
import {
  buildDependencyGraph,
  buildRemediationPlan,
  type ScanResult,
  type ScanVulnerability,
} from "@fixly/core";
import { buildFixBrief, buildPackageBrief } from "../src/brief";

function vuln(over: Partial<ScanVulnerability> = {}): ScanVulnerability {
  return {
    osvId: "GHSA-xxxx",
    cveId: "CVE-2024-0001",
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
    references: ["https://example.com/advisory"],
    ...over,
  };
}

function result(vulnerabilities: ScanVulnerability[]): ScanResult {
  return {
    repo: "demo",
    scannedAt: "2026-08-04T00:00:00Z",
    source: "osv",
    totalPackages: 5,
    directPackages: 3,
    transitivePackages: 2,
    resolvedPackages: 5,
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
  };
}

function briefFor(
  vulns: ScanVulnerability[],
  graph: ReturnType<typeof buildDependencyGraph> = null
): string {
  const scan = result(vulns);
  return buildFixBrief(scan, buildRemediationPlan(scan, { graph }));
}

const blockedGraph = () =>
  buildDependencyGraph({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { "left-pad": "^1.0.0", consumer: "^1.0.0" } },
      "node_modules/left-pad": { version: "1.0.0" },
      "node_modules/consumer": {
        version: "1.0.0",
        dependencies: { "left-pad": "~1.0.0" },
      },
    },
  });

describe("buildFixBrief — sections", () => {
  it("a direct patch upgrade includes target, path, jump, risk, rationale, and the command", () => {
    const brief = briefFor([vuln()]);
    expect(brief).toContain("# Fixly fix brief — demo");
    expect(brief).toContain("## left-pad@1.0.0 → 1.0.5 — direct upgrade (patch jump, low risk)");
    expect(brief).toContain("GHSA-xxxx (CVE-2024-0001) — high, CVSS 7.5");
    expect(brief).toContain("Minimum safe target: 1.0.5");
    expect(brief).toContain("Resolution path: DIRECT");
    expect(brief).toContain("Semver jump: PATCH");
    expect(brief).toContain("Risk: low");
    expect(brief).toContain("Why: ");
    expect(brief).toContain("    npm install left-pad@1.0.5");
    expect(brief).toContain("run `npm install` and rescan with Fixly");
    expect(brief).toContain("never modifies");
  });

  it("a direct major upgrade is labeled a major jump with elevated risk", () => {
    const brief = briefFor([vuln({ fixedVersion: "2.0.0" })]);
    expect(brief).toContain("→ 2.0.0 — direct upgrade (major jump, elevated risk)");
    expect(brief).toContain("Semver jump: MAJOR");
    expect(brief).toContain("Risk: elevated");
  });

  it("a transitive override includes the exact overrides JSON", () => {
    const brief = briefFor([vuln({ dependencyType: "transitive" })]);
    expect(brief).toContain("transitive — pin via npm overrides");
    expect(brief).toContain("Resolution path: TRANSITIVE_OVERRIDE");
    expect(brief).toContain('"overrides": {');
    expect(brief).toContain('"left-pad": "1.0.5"');
    expect(brief).toContain("npm pkg set overrides.left-pad=1.0.5 && npm install");
  });

  it("BLOCKED_BY_PARENT names the blocker, forbids forcing, and offers no command", () => {
    const brief = briefFor([vuln({ fixedVersion: "1.1.0" })], blockedGraph());
    expect(brief).toContain("## left-pad@1.0.0 — BLOCKED_BY_PARENT (no safe edit exists)");
    expect(brief).toContain('consumer@1.0.0 requires "~1.0.0"');
    expect(brief).toContain("Do NOT force an incompatible version");
    expect(brief).not.toContain("npm install left-pad@");
  });

  it("NO_FIX_AVAILABLE is a legitimate state with no command", () => {
    const brief = briefFor([vuln({ fixedVersion: null })]);
    expect(brief).toContain("## No fix available yet (NO_FIX_AVAILABLE)");
    expect(brief).toContain("left-pad@1.0.0 — GHSA-xxxx (high)");
    expect(brief).toContain("a legitimate state, not an error");
    expect(brief).not.toContain("npm install left-pad");
  });

  it("malware is a REMOVE section that never suggests upgrading", () => {
    const brief = briefFor([vuln({ malicious: true, osvId: "MAL-0001", cveId: null })]);
    expect(brief).toContain("## left-pad@1.0.0 — REMOVE (known malicious)");
    expect(brief).toContain("malware, not a bug");
    expect(brief).toContain("npm uninstall left-pad");
    expect(brief).not.toContain("→ 1.0.5");
  });

  it("multiple advisories on one package land in one section; unfixed leftovers are noted", () => {
    const brief = briefFor([
      vuln(),
      vuln({ osvId: "GHSA-yyyy", cveId: null, severity: "medium", fixedVersion: "1.0.2" }),
      vuln({ osvId: "GHSA-zzzz", cveId: null, severity: "low", fixedVersion: null }),
    ]);
    expect(brief).toContain("Advisories (2):");
    expect(brief).toContain("GHSA-xxxx");
    expect(brief).toContain("GHSA-yyyy");
    expect(brief).toContain("Note: 1 advisory on this package (GHSA-zzzz) has no published fix");
    // the leftover is folded into the action's note, not duplicated below it
    expect(brief).not.toContain("## No fix available yet");
  });

  it("a missing CVSS score is omitted, never invented", () => {
    const brief = briefFor([vuln({ cvssScore: null })]);
    expect(brief).toContain("— high — A vulnerability");
    expect(brief).not.toContain("CVSS");
  });

  it("scoped package names survive in headers, commands, and overrides JSON", () => {
    const brief = briefFor([
      vuln({ package: "@scope/pkg", dependencyType: "transitive" }),
    ]);
    expect(brief).toContain("## @scope/pkg@1.0.0 → 1.0.5");
    expect(brief).toContain('"@scope/pkg": "1.0.5"');
  });

  it("a clean scan yields an honest empty brief", () => {
    const brief = briefFor([]);
    expect(brief).toContain("No known vulnerabilities — nothing to fix.");
  });

  it("is deterministic: same scan, same brief, byte for byte", () => {
    const vulns = [
      vuln(),
      vuln({ package: "qs", installedVersion: "6.2.0", fixedVersion: "6.2.4", dependencyType: "transitive", osvId: "GHSA-qqqq" }),
      vuln({ package: "abandoned", fixedVersion: null, osvId: "GHSA-aaaa" }),
    ];
    expect(briefFor(vulns)).toEqual(briefFor(vulns));
  });
});

describe("buildPackageBrief", () => {
  const mixed = () => [
    vuln(),
    vuln({ package: "qs", installedVersion: "6.2.0", fixedVersion: "6.2.4", dependencyType: "transitive", osvId: "GHSA-qqqq" }),
  ];

  it("renders only the requested package", () => {
    const scan = result(mixed());
    const plan = buildRemediationPlan(scan);
    const brief = buildPackageBrief(scan, plan, "qs")!;
    expect(brief).toContain("# Fixly fix brief — qs");
    expect(brief).toContain('"qs": "6.2.4"');
    expect(brief).not.toContain("left-pad");
    expect(brief).toContain("never modifies");
  });

  it("returns null for a package with no findings", () => {
    const scan = result(mixed());
    const plan = buildRemediationPlan(scan);
    expect(buildPackageBrief(scan, plan, "express")).toBeNull();
  });

  it("covers blocked and no-fix packages too", () => {
    const scanBlocked = result([vuln({ fixedVersion: "1.1.0" })]);
    const planBlocked = buildRemediationPlan(scanBlocked, { graph: blockedGraph() });
    expect(buildPackageBrief(scanBlocked, planBlocked, "left-pad")).toContain(
      "BLOCKED_BY_PARENT"
    );

    const scanNoFix = result([vuln({ fixedVersion: null })]);
    const planNoFix = buildRemediationPlan(scanNoFix);
    expect(buildPackageBrief(scanNoFix, planNoFix, "left-pad")).toContain(
      "No fix available yet"
    );
  });
});
