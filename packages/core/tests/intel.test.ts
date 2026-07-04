import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { enrichWithIntel, clearIntelCache, isNewlyExploited } from "../src/intel";
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
    kevDateAdded: null,
    pocCount: null,
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

  it("stamps kevDateAdded and flags newly-added KEV entries", async () => {
    const recent = new Date(Date.now() - 5 * 86_400_000).toISOString().slice(0, 10);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.includes("cisa.gov")
          ? jsonRes({ vulnerabilities: [{ cveID: "CVE-2024-0001", dateAdded: recent }] })
          : jsonRes({ data: [] })
      )
    );
    const { vulnerabilities } = await enrichWithIntel([finding("CVE-2024-0001")]);
    expect(vulnerabilities[0].knownExploited).toBe(true);
    expect(vulnerabilities[0].kevDateAdded).toBe(recent);
    expect(isNewlyExploited(vulnerabilities[0].kevDateAdded)).toBe(true);
    expect(isNewlyExploited("2000-01-01")).toBe(false);
  });

  it("stamps public PoC counts from the nomi-sec feed (404 = 0)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.includes("cisa.gov")) return jsonRes({ vulnerabilities: [] });
        if (url.includes("first.org")) return jsonRes({ data: [] });
        if (url.includes("PoC-in-GitHub")) {
          if (url.includes("CVE-2021-0001")) {
            return jsonRes([{ html_url: "a" }, { html_url: "b" }, { html_url: "c" }]);
          }
          return { status: 404, ok: false, json: async () => ({}), text: async () => "" };
        }
        return jsonRes({});
      })
    );
    const { vulnerabilities } = await enrichWithIntel([
      finding("CVE-2021-0001"),
      finding("CVE-2020-0002"),
    ]);
    expect(vulnerabilities[0].pocCount).toBe(3);
    expect(vulnerabilities[1].pocCount).toBe(0);
  });

  it("unions the VulnCheck KEV catalog when VULNCHECK_API_KEY is set", async () => {
    const prev = process.env.VULNCHECK_API_KEY;
    process.env.VULNCHECK_API_KEY = "test-key";
    try {
      let sawBearer = false;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string, init?: RequestInit) => {
          if (url.includes("cisa.gov")) return jsonRes({ vulnerabilities: [] }); // CISA empty
          if (url.includes("vulncheck.com")) {
            const auth = (init?.headers as Record<string, string> | undefined)?.Authorization;
            if (auth === "Bearer test-key") sawBearer = true;
            return jsonRes({
              data: [{ cve: ["CVE-2099-0001"], date_added: "2099-01-01" }],
              _meta: { total_pages: 1 },
            });
          }
          return jsonRes({ data: [] });
        })
      );
      const { vulnerabilities } = await enrichWithIntel([finding("CVE-2099-0001")]);
      expect(sawBearer).toBe(true);
      expect(vulnerabilities[0].knownExploited).toBe(true); // from VulnCheck, not CISA
      expect(vulnerabilities[0].kevDateAdded).toBe("2099-01-01");
    } finally {
      if (prev === undefined) delete process.env.VULNCHECK_API_KEY;
      else process.env.VULNCHECK_API_KEY = prev;
      clearIntelCache();
    }
  });
});
