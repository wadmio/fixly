import { describe, it, expect } from "vitest";
import { buildDependencyGraph, type ScanResult, type ScanVulnerability } from "@fixly/core";
import { escapeHtml, buildSummaryText, renderHtml } from "../src/panel-render";

function vuln(over: Partial<ScanVulnerability> = {}): ScanVulnerability {
  return {
    osvId: "GHSA-xxxx",
    cveId: "CVE-2024-0001",
    package: "left-pad",
    installedVersion: "1.0.0",
    fixedVersion: "1.3.0",
    severity: "high",
    cvssVector: null,
    cvssScore: 7.5,
    affectedRanges: ["<1.3.0"],
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

function result(over: Partial<ScanResult> = {}): ScanResult {
  return {
    repo: "owner/repo",
    scannedAt: "2026-01-01T00:00:00Z",
    source: "osv",
    totalPackages: 2,
    directPackages: 1,
    transitivePackages: 1,
    resolvedPackages: 2,
    dependencies: [],
    vulnerabilities: [vuln()],
    target: {
      owner: "owner",
      repo: "repo",
      branch: "main",
      subpath: null,
      filesFound: ["package.json", "package-lock.json"],
      filesMissing: [],
    },
    warnings: [],
    ...over,
  } as ScanResult;
}

describe("escapeHtml", () => {
  it("neutralizes HTML metacharacters", () => {
    expect(escapeHtml(`<script>alert("x")</script>`)).toBe(
      "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
    );
    expect(escapeHtml("a & b")).toBe("a &amp; b");
  });
});

describe("buildSummaryText", () => {
  it("leads with the Fixly Score and marks transitive findings", () => {
    const text = buildSummaryText(
      result({ vulnerabilities: [vuln({ dependencyType: "transitive", severity: "critical" })] })
    );
    expect(text).toContain("Fixly Score:");
    expect(text).toMatch(/Fixly Score: [A-F] \(\d+\/100\)/);
    expect(text).toContain("(transitive)");
  });
});

describe("renderHtml", () => {
  it("escapes a malicious finding title (no raw script injection)", () => {
    const html = renderHtml(
      result({ vulnerabilities: [vuln({ title: `<img src=x onerror=alert(1)>` })] }),
      "test-nonce"
    );
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("includes the Fixly Score card and a strict webview CSP", () => {
    const html = renderHtml(result(), "test-nonce");
    expect(html).toContain("Fixly Score");
    expect(html).toContain('class="score-letter"');
    expect(html).toContain("default-src 'none'");
    expect(html).toContain("nonce-test-nonce");
  });

  it("renders a clean state when there are no vulnerabilities", () => {
    const html = renderHtml(result({ vulnerabilities: [] }), "n");
    expect(html).toContain("No vulnerabilities found");
  });

  it("offers the Copy Fix Brief action (copy-only; no apply control exists)", () => {
    const html = renderHtml(result(), "n");
    expect(html).toContain('id="brief"');
    expect(html).toContain("Copy Fix Brief");
    expect(html).toContain('postMessage({ type: "copyBrief" })');
    expect(html).not.toMatch(/apply/i);
  });
});

describe("renderHtml — remediation plan classification", () => {
  it("shows the plan with a calm chip for a patch-level direct fix and its rationale", () => {
    const html = renderHtml(
      result({ vulnerabilities: [vuln({ installedVersion: "1.2.0", fixedVersion: "1.2.9" })] }),
      "n"
    );
    expect(html).toContain("Remediation Plan");
    expect(html).toContain('class="chip risk-low">patch</span>');
    expect(html).toContain("patch-level bump");
  });

  it("marks a MAJOR jump and a transitive override as visually elevated", () => {
    const html = renderHtml(
      result({
        vulnerabilities: [
          vuln({ package: "big-jump", installedVersion: "1.0.0", fixedVersion: "2.0.0" }),
          vuln({
            package: "deep",
            osvId: "GHSA-deep",
            dependencyType: "transitive",
            installedVersion: "1.0.0",
            fixedVersion: "1.0.1",
          }),
        ],
      }),
      "n"
    );
    expect(html).toContain('class="chip risk-elevated" title="May contain breaking changes — review the changelog">major</span>');
    expect(html).toContain(">override</span>");
  });

  it("renders the Blocked section when a parent range forbids the fix", () => {
    const graph = buildDependencyGraph({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { parent: "^3.0.0" } },
        "node_modules/parent": { version: "3.0.0", dependencies: { pinned: "~1.0.0" } },
        "node_modules/pinned": { version: "1.0.0" },
      },
    });
    const html = renderHtml(
      result({
        vulnerabilities: [
          vuln({
            package: "pinned",
            osvId: "GHSA-blocked",
            dependencyType: "transitive",
            installedVersion: "1.0.0",
            fixedVersion: "1.1.0",
          }),
        ],
      }),
      "n",
      graph
    );
    expect(html).toContain("Blocked — a fix exists, but no safe edit is available");
    expect(html).toContain("parent@3.0.0 requires &quot;~1.0.0&quot;");
    // Advice-only: the report never renders an apply control.
    expect(html).not.toContain('id="apply"');
  });

  it("lists findings with no published fix", () => {
    const html = renderHtml(
      result({ vulnerabilities: [vuln({ osvId: "GHSA-stuck", fixedVersion: null })] }),
      "n"
    );
    expect(html).toContain("No fix published yet");
    expect(html).toContain("GHSA-stuck");
  });

  it("escapes rationale text like any other third-party-derived string", () => {
    const html = renderHtml(
      result({ vulnerabilities: [vuln({ package: "<script>x</script>" })] }),
      "n"
    );
    expect(html).not.toContain("<script>x</script>");
  });
});
