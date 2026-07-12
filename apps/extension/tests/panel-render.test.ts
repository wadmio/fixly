import { describe, it, expect } from "vitest";
import type { ScanResult, ScanVulnerability } from "@fixly/core";
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
    expect(html).not.toContain("Fix Everything");
  });

  it("shows the Fix Everything button and Grade Forecast when fixes exist", () => {
    const html = renderHtml(result(), "n");
    expect(html).toContain("Fix Everything &amp; Verify");
    expect(html).toContain("Fix everything →");
    expect(html).toContain('id="fixall"');
  });

  it("renders the guardian activity feed with MTTR badges, escaped", () => {
    const html = renderHtml(result(), "n", [
      { at: "18:19:59", kind: "remediated", text: "remediated 1 package <b>x</b>", mttrMs: 3200 },
      { at: "18:19:55", kind: "detected", text: "5 new findings in lodash" },
    ]);
    expect(html).toContain("Guardian activity");
    expect(html).toContain("MTTR 3.2s");
    expect(html).toContain("remediated 1 package &lt;b&gt;x&lt;/b&gt;");
    expect(html).not.toContain("<b>x</b>");
  });

  it("omits the activity feed when there is no activity", () => {
    const html = renderHtml(result(), "n");
    expect(html).not.toContain("Guardian activity");
  });
});
