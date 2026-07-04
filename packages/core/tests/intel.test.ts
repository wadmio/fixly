import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { enrichWithIntel, clearIntelCache } from "../src/intel";
import type { ScanVulnerability } from "../src/types";

function finding(cveId: string | null): ScanVulnerability {
  return {
    osvId: `GHSA-${cveId ?? "none"}`,
    cveId,
    package: "pkg",
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

function jsonRes(body: unknown) {
  return { status: 200, ok: true, json: async () => body, text: async () => "" };
}

describe("enrichWithIntel", () => {
  beforeEach(() => clearIntelCache());
  afterEach(() => vi.unstubAllGlobals());

  it("flags KEV-listed CVEs and stamps EPSS scores", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("cisa.gov")) {
          return jsonRes({ vulnerabilities: [{ cveID: "CVE-2024-0001" }] });
        }
        return jsonRes({
          data: [
            { cve: "CVE-2024-0001", epss: "0.92", percentile: "0.99" },
            { cve: "CVE-2024-0002", epss: "0.01", percentile: "0.30" },
          ],
        });
      })
    );

    const { vulnerabilities, warnings } = await enrichWithIntel([
      finding("CVE-2024-0001"),
      finding("CVE-2024-0002"),
      finding(null),
    ]);

    expect(warnings).toEqual([]);
    expect(vulnerabilities[0].knownExploited).toBe(true);
    expect(vulnerabilities[0].epssScore).toBeCloseTo(0.92);
    expect(vulnerabilities[1].knownExploited).toBe(false);
    expect(vulnerabilities[1].epssScore).toBeCloseTo(0.01);
    expect(vulnerabilities[2].knownExploited).toBe(false);
    expect(vulnerabilities[2].epssScore).toBeNull();
  });

  it("caches the KEV catalog across calls", async () => {
    const fetchMock = vi.fn(async (url: string) =>
      url.includes("cisa.gov")
        ? jsonRes({ vulnerabilities: [] })
        : jsonRes({ data: [] })
    );
    vi.stubGlobal("fetch", fetchMock);

    await enrichWithIntel([finding("CVE-2024-0001")]);
    await enrichWithIntel([finding("CVE-2024-0001")]);

    const kevCalls = fetchMock.mock.calls.filter(([u]) => String(u).includes("cisa.gov"));
    expect(kevCalls).toHaveLength(1);
  });

  it("degrades to warnings when both feeds are down — never throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ status: 503, ok: false, json: async () => ({}), text: async () => "" }))
    );
    const { vulnerabilities, warnings } = await enrichWithIntel([finding("CVE-2024-0001")]);
    expect(vulnerabilities[0].knownExploited).toBe(false);
    expect(warnings).toHaveLength(2);
  });

  it("skips the network entirely when no finding has a CVE", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await enrichWithIntel([finding(null)]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
