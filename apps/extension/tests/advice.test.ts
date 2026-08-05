import { describe, it, expect } from "vitest";
import {
  buildDependencyGraph,
  buildRemediationPlan,
  type ScanResult,
  type ScanVulnerability,
} from "@fixly/core";
import { adviceForScan } from "../src/advice";

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

function adviceFor(vulns: ScanVulnerability[], graph: ReturnType<typeof buildDependencyGraph> = null) {
  const scan = result(vulns);
  return adviceForScan(scan, buildRemediationPlan(scan, { graph }));
}

describe("diagnostic tier — risk + CVSS, not CVSS alone", () => {
  it("malicious and known-exploited findings are errors regardless of CVSS", () => {
    expect(adviceFor([vuln({ severity: "low", knownExploited: true })]).get("left-pad")!.tier).toBe("error");
    expect(adviceFor([vuln({ severity: "low", malicious: true, osvId: "MAL-1" })]).get("left-pad")!.tier).toBe("error");
  });

  it("critical/high → error, medium → warning", () => {
    expect(adviceFor([vuln({ severity: "critical" })]).get("left-pad")!.tier).toBe("error");
    expect(adviceFor([vuln({ severity: "medium" })]).get("left-pad")!.tier).toBe("warning");
  });

  it("a low finding with a calm patch fix is info, but with a MAJOR fix it is a warning", () => {
    expect(
      adviceFor([vuln({ severity: "low", fixedVersion: "1.0.5" })]).get("left-pad")!.tier
    ).toBe("info");
    expect(
      adviceFor([vuln({ severity: "low", fixedVersion: "2.0.0" })]).get("left-pad")!.tier
    ).toBe("warning");
  });

  it("unknown severity stays a hint", () => {
    expect(adviceFor([vuln({ severity: "unknown" })]).get("left-pad")!.tier).toBe("hint");
  });
});

describe("diagnostic message — remediation clause", () => {
  it("a patch-level direct fix reads calm", () => {
    const a = adviceFor([vuln()]).get("left-pad")!;
    expect(a.message).toContain("worst is high (CVE-2024-0001)");
    expect(a.message).toContain("Patched in 1.0.5 — patch bump, direct dep, low risk.");
  });

  it("a MAJOR fix warns about breaking changes", () => {
    const a = adviceFor([vuln({ fixedVersion: "2.0.0" })]).get("left-pad")!;
    expect(a.message).toContain(
      "Fix requires major bump 1.0.0 → 2.0.0 — breaking API changes likely."
    );
  });

  it("NO_FIX_AVAILABLE is stated as a state, not an error", () => {
    const a = adviceFor([vuln({ fixedVersion: null })]).get("left-pad")!;
    expect(a.message).toContain("No fixed release published yet.");
  });

  it("malware says remove, never upgrade", () => {
    const a = adviceFor([vuln({ malicious: true, osvId: "MAL-1" })]).get("left-pad")!;
    expect(a.message).toContain("MALICIOUS");
    expect(a.message).toContain("remove");
  });

  it("BLOCKED_BY_PARENT names the blocking parent and range", () => {
    // left-pad is a DIRECT dep, but installed dependent "consumer" pins ~1.0.0
    // while the only fix is 1.1.0 → blocked.
    const graph = buildDependencyGraph({
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
    const a = adviceFor([vuln({ fixedVersion: "1.1.0" })], graph).get("left-pad")!;
    expect(a.message).toContain('consumer@1.0.0 requires "~1.0.0"');
    expect(a.message).toContain("blocked");
  });
});

describe("hover markdown", () => {
  it("shows the advisory list and the remediation card with the command", () => {
    const md = adviceFor([
      vuln(),
      vuln({ osvId: "GHSA-yyyy", cveId: null, severity: "medium", title: "Another one" }),
    ]).get("left-pad")!.hoverMarkdown;
    expect(md).toContain("**left-pad@1.0.0** — 2 advisories (worst: **high**)");
    expect(md).toContain("[GHSA-xxxx](https://example.com/advisory)");
    expect(md).toContain("**Remediation — direct upgrade**");
    expect(md).toContain("patch bump, low risk");
    expect(md).toContain("npm install left-pad@1.0.5");
    expect(md).toContain("never modifies");
  });

  it("blocked and no-fix states get their own hover copy, with no command fence", () => {
    const noFix = adviceFor([vuln({ fixedVersion: null })]).get("left-pad")!.hoverMarkdown;
    expect(noFix).toContain("no fix available yet");
    expect(noFix).toContain("a legitimate state, not an error");
    expect(noFix).not.toContain("```");

    const graph = buildDependencyGraph({
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
    const blocked = adviceFor([vuln({ fixedVersion: "1.1.0" })], graph).get("left-pad")!.hoverMarkdown;
    expect(blocked).toContain("blocked by parent");
    expect(blocked).toContain("consumer@1.0.0 requires `~1.0.0`");
    expect(blocked).not.toContain("```");
  });

  it("escapes markdown metacharacters in third-party advisory titles", () => {
    const md = adviceFor([vuln({ title: "evil [link](https://x) *bold* `tick`" })]).get(
      "left-pad"
    )!.hoverMarkdown;
    expect(md).not.toContain("[link](https://x)");
    expect(md).toContain("\\[link\\]");
  });
});

describe("scope", () => {
  it("transitive findings get no advice entry (no line to squiggle)", () => {
    const advice = adviceFor([
      vuln(),
      vuln({ package: "deep", dependencyType: "transitive" }),
    ]);
    expect(advice.has("left-pad")).toBe(true);
    expect(advice.has("deep")).toBe(false);
  });
});
