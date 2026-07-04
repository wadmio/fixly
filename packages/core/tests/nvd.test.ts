import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { enrichWithNvd, clearNvdCache } from "../src/nvd";
import type { ScanVulnerability } from "../src/types";

function finding(cveId: string | null, pkg = "pkg"): ScanVulnerability {
  return {
    osvId: `GHSA-${pkg}-${cveId ?? "none"}`,
    cveId,
    package: pkg,
    installedVersion: "1.0.0",
    fixedVersion: null,
    severity: "high",
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
    title: "t",
    description: "",
    references: [],
  };
}

function nvdRes(baseScore: number, baseSeverity: string) {
  return {
    status: 200,
    ok: true,
    json: async () => ({
      vulnerabilities: [
        {
          cve: {
            metrics: {
              cvssMetricV31: [
                {
                  cvssData: {
                    baseScore,
                    baseSeverity,
                    vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  },
                },
              ],
            },
          },
        },
      ],
    }),
    text: async () => "",
  };
}

describe("enrichWithNvd", () => {
  beforeEach(() => clearNvdCache());
  afterEach(() => vi.unstubAllGlobals());

  it("adds NVD data and the nvd source to findings with a CVE", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => nvdRes(9.8, "CRITICAL")));
    const { vulnerabilities, enrichedCount } = await enrichWithNvd([
      finding("CVE-2024-0001"),
      finding(null, "other"),
    ]);
    expect(enrichedCount).toBe(1);
    expect(vulnerabilities[0].sources).toEqual(["osv", "nvd"]);
    expect(vulnerabilities[0].nvd).toEqual({
      cvssScore: 9.8,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      severity: "critical",
    });
    // The no-CVE finding is untouched.
    expect(vulnerabilities[1].sources).toEqual(["osv"]);
    expect(vulnerabilities[1].nvd).toBeNull();
  });

  it("caps unauthenticated fetches at 5 unique CVEs and warns about coverage", async () => {
    const fetchMock = vi.fn(async () => nvdRes(7.5, "HIGH"));
    vi.stubGlobal("fetch", fetchMock);
    const findings = Array.from({ length: 8 }, (_, i) => finding(`CVE-2024-000${i}`));
    const { warnings, enrichedCount } = await enrichWithNvd(findings, { apiKey: undefined });
    expect(fetchMock).toHaveBeenCalledTimes(5);
    expect(enrichedCount).toBe(5);
    expect(warnings.some((w) => w.includes("covered 5 of 8"))).toBe(true);
  });

  it("serves repeated CVEs from the cache without refetching", async () => {
    const fetchMock = vi.fn(async () => nvdRes(7.5, "HIGH"));
    vi.stubGlobal("fetch", fetchMock);
    await enrichWithNvd([finding("CVE-2024-0001")]);
    await enrichWithNvd([finding("CVE-2024-0001")]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("degrades to a warning when NVD is unreachable — never throws", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ status: 503, ok: false, json: async () => ({}), text: async () => "down" })));
    const { vulnerabilities, warnings, enrichedCount } = await enrichWithNvd(
      [finding("CVE-2024-0001")],
      { timeBudgetMs: 2_000 }
    );
    expect(enrichedCount).toBe(0);
    expect(vulnerabilities[0].sources).toEqual(["osv"]);
    expect(warnings.some((w) => w.includes("NVD cross-check unavailable"))).toBe(true);
  });

  it("returns immediately when no finding has a CVE", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { warnings, enrichedCount } = await enrichWithNvd([finding(null)]);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(enrichedCount).toBe(0);
    expect(warnings).toEqual([]);
  });
});
