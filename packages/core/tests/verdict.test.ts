import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { checkPackage } from "../src/verdict";
import { clearRegistryCache } from "../src/registry";
import { clearIntelCache } from "../src/intel";

function jsonRes(status: number, body: unknown) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

/** Route-based fetch stub: pass handlers keyed by URL substring. */
function stubRoutes(routes: Array<[string, (url: string, init?: RequestInit) => unknown]>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      for (const [needle, handler] of routes) {
        if (url.includes(needle)) return handler(url, init);
      }
      return jsonRes(404, {});
    })
  );
}

const packument = (over: Record<string, unknown> = {}) => ({
  "dist-tags": { latest: "2.0.0" },
  time: {
    created: new Date(Date.now() - 400 * 86_400_000).toISOString(),
    modified: new Date(Date.now() - 5 * 86_400_000).toISOString(),
  },
  maintainers: [{}, {}],
  versions: { "1.0.0": {}, "2.0.0": {} },
  ...over,
});

describe("checkPackage", () => {
  beforeEach(() => {
    clearRegistryCache();
    clearIntelCache();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("BLOCKs a package that does not exist (hallucination/slopsquat)", async () => {
    stubRoutes([["registry.npmjs.org", () => jsonRes(404, {})]]);
    const v = await checkPackage("definitely-not-a-real-pkg-xyz", null, { intel: false });
    expect(v.verdict).toBe("block");
    expect(v.reasons[0]).toContain("does not exist");
    expect(v.reasons[0]).toContain("slopsquatting");
  });

  it("suggests the real package for a nonexistent near-miss name", async () => {
    stubRoutes([["registry.npmjs.org", () => jsonRes(404, {})]]);
    const v = await checkPackage("lodahs", null, { intel: false });
    expect(v.verdict).toBe("block");
    expect(v.reasons[0]).toContain('did you mean "lodash"');
  });

  it("BLOCKs on an OSV MAL- malicious-package record", async () => {
    stubRoutes([
      ["api.osv.dev/v1/query", () => jsonRes(200, { vulns: [{ id: "MAL-2026-1234", summary: "malware" }] })],
      ["registry.npmjs.org", () => jsonRes(200, packument())],
      ["api.npmjs.org", () => jsonRes(200, { downloads: 12000 })],
    ]);
    const v = await checkPackage("evil-pkg", "2.0.0", { intel: false });
    expect(v.verdict).toBe("block");
    expect(v.reasons[0]).toContain("MALICIOUS");
    expect(v.signals.maliciousIds).toEqual(["MAL-2026-1234"]);
  });

  it("BLOCKs when a CVE is in the CISA KEV catalog", async () => {
    stubRoutes([
      [
        "api.osv.dev/v1/query",
        () =>
          jsonRes(200, {
            vulns: [
              {
                id: "GHSA-x",
                aliases: ["CVE-2024-9999"],
                database_specific: { severity: "CRITICAL" },
              },
            ],
          }),
      ],
      ["cisa.gov", () => jsonRes(200, { vulnerabilities: [{ cveID: "CVE-2024-9999" }] })],
      ["api.first.org", () => jsonRes(200, { data: [{ cve: "CVE-2024-9999", epss: "0.95", percentile: "0.99" }] })],
      ["registry.npmjs.org", () => jsonRes(200, packument())],
      ["api.npmjs.org", () => jsonRes(200, { downloads: 50000 })],
    ]);
    const v = await checkPackage("some-lib", "1.0.0");
    expect(v.verdict).toBe("block");
    expect(v.reasons[0]).toContain("CVE-2024-9999");
    expect(v.reasons[0]).toContain("Known Exploited");
    expect(v.signals.maxEpss).toBeCloseTo(0.95);
  });

  it("CAUTIONs a brand-new obscure package with install scripts", async () => {
    stubRoutes([
      ["api.osv.dev/v1/query", () => jsonRes(200, { vulns: [] })],
      [
        "registry.npmjs.org",
        () =>
          jsonRes(
            200,
            packument({
              time: {
                created: new Date(Date.now() - 3 * 86_400_000).toISOString(),
                modified: new Date().toISOString(),
              },
              versions: { "2.0.0": { hasInstallScript: true } },
            })
          ),
      ],
      ["api.npmjs.org", () => jsonRes(200, { downloads: 12 })],
    ]);
    const v = await checkPackage("shiny-new-helper", null, { intel: false });
    expect(v.verdict).toBe("caution");
    expect(v.reasons.join(" ")).toContain("Brand new");
    expect(v.reasons.join(" ")).toContain("install scripts");
  });

  it("SAFEs a curated-popular package with a clean OSV record", async () => {
    stubRoutes([
      ["registry.npmjs.org/lodash/latest", () => jsonRes(200, { version: "4.17.21" })],
      ["api.osv.dev/v1/query", () => jsonRes(200, { vulns: [] })],
    ]);
    const v = await checkPackage("lodash", null, { intel: false });
    expect(v.verdict).toBe("safe");
    expect(v.evaluatedVersion).toBe("4.17.21");
    expect(v.signals.popular).toBe(true);
    expect(v.summary).toContain("looks safe");
  });

  it("says 'could not check' instead of 'safe' when everything is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      })
    );
    const v = await checkPackage("some-obscure-lib", "1.0.0", { intel: false });
    expect(v.warnings.length).toBeGreaterThan(0);
    expect(v.warnings.join(" ")).toContain("registry was unreachable");
    expect(v.signals.exists).toBeNull(); // unknown, NOT false
    // Fail-safe, not fail-open: a package we couldn't check is NOT "safe".
    expect(v.verdict).toBe("unknown");
    expect(v.summary).toContain("COULD NOT VERIFY");
  });

  it("does NOT downgrade to unknown when OSV is deliberately disabled and the registry is clean", async () => {
    // A caller opting out of OSV (offline name-only check) still gets a real
    // SAFE from the registry+typosquat signals — opt-out is not "couldn't check".
    stubRoutes([
      ["registry.npmjs.org", () => jsonRes(200, packument())],
      ["api.npmjs.org", () => jsonRes(200, { downloads: 40000 })],
    ]);
    const v = await checkPackage("some-established-lib", "2.0.0", { osv: false, intel: false });
    expect(v.verdict).toBe("safe");
  });
});
