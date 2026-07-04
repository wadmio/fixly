import { describe, it, expect } from "vitest";
import { normalizeOsvResults } from "../src/normalize";
import type { OsvVuln } from "../src/osv";

function normalizeOne(vuln: OsvVuln) {
  return normalizeOsvResults("pkg", "1.0.0", [vuln])[0];
}

describe("normalizeOsvResults — severity", () => {
  it("reads top-level database_specific severity (HIGH)", () => {
    expect(normalizeOne({ id: "GHSA-1", database_specific: { severity: "HIGH" } }).severity).toBe(
      "high"
    );
  });

  it("maps MODERATE to medium", () => {
    expect(
      normalizeOne({ id: "GHSA-2", database_specific: { severity: "MODERATE" } }).severity
    ).toBe("medium");
  });

  it("computes severity and CVSS score from a CVSS v3 vector", () => {
    const v = normalizeOne({
      id: "GHSA-3",
      severity: [
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      ],
    });
    expect(v.severity).toBe("critical");
    expect(v.cvssScore).toBe(9.8);
  });

  it("computes the scope-changed (S:C) branch against known spec vectors", () => {
    // Reflected XSS — the canonical CVSS v3.1 6.1 vector.
    const xss = normalizeOne({
      id: "GHSA-8",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" }],
    });
    expect(xss.cvssScore).toBe(6.1);
    expect(xss.severity).toBe("medium");

    // Scope-changed, full impact, network, no barriers → 10.0.
    const worst = normalizeOne({
      id: "GHSA-9",
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
    });
    expect(worst.cvssScore).toBe(10.0);
    expect(worst.severity).toBe("critical");
  });

  it("falls back to unknown when no severity data is present", () => {
    const v = normalizeOne({ id: "GHSA-4" });
    expect(v.severity).toBe("unknown");
    expect(v.cvssScore).toBeNull();
  });

  it("derives a severity band from a CVSS v4 vector instead of returning unknown", () => {
    // Full-impact, network, no barriers → critical band. No numeric score is
    // fabricated (v4 base score needs the official lookup table), but the
    // vector string is surfaced.
    const v = normalizeOne({
      id: "CVE-2025-9",
      severity: [
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
      ],
    });
    expect(v.severity).toBe("critical");
    expect(v.cvssScore).toBeNull();
    expect(v.cvssVector).toContain("CVSS:4.0");
  });

  it("bands a low-impact CVSS v4 vector as low, not critical", () => {
    const v = normalizeOne({
      id: "CVE-2025-10",
      severity: [
        { type: "CVSS_V4", score: "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N" },
      ],
    });
    expect(v.severity).toBe("low");
  });

  it("prefers a computable v3 vector over a v4 vector listed first", () => {
    const v = normalizeOne({
      id: "CVE-2025-11",
      severity: [
        { type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N" },
        { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
      ],
    });
    expect(v.severity).toBe("critical");
    expect(v.cvssScore).toBe(9.8);
  });
});

describe("normalizeOsvResults — fields", () => {
  it("extracts the CVE alias and fixed version", () => {
    const v = normalizeOne({
      id: "GHSA-5",
      aliases: ["CVE-2024-0001", "GHSA-xxxx"],
      affected: [{ ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.1.0" }] }] }],
    });
    expect(v.cveId).toBe("CVE-2024-0001");
    expect(v.fixedVersion).toBe("2.1.0");
  });

  it("includes affected ranges and confirms the installed version is in range", () => {
    const v = normalizeOsvResults("pkg", "1.0.0", [
      {
        id: "GHSA-6",
        affected: [
          { package: { name: "pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.1.0" }] }] },
        ],
      },
    ])[0];
    expect(v.affectedRanges).toEqual(["<2.1.0"]);
    expect(v.versionInRange).toBe(true);
  });

  it("keeps only http(s) reference URLs (drops javascript:/data: XSS vectors)", () => {
    const v = normalizeOne({
      id: "GHSA-ref",
      references: [
        { type: "WEB", url: "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" },
        { type: "WEB", url: "javascript:alert(document.cookie)" },
        { type: "WEB", url: "data:text/html,<script>alert(1)</script>" },
        { type: "WEB", url: "http://example.com/advisory" },
      ],
    });
    expect(v.references).toEqual([
      "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
      "http://example.com/advisory",
    ]);
  });

  it("defaults versionSource to lockfile and passes through range-minimum", () => {
    const base = { id: "GHSA-7" };
    expect(normalizeOsvResults("pkg", "1.0.0", [base])[0].versionSource).toBe("lockfile");
    expect(
      normalizeOsvResults("pkg", "1.0.0", [base], "range-minimum")[0].versionSource
    ).toBe("range-minimum");
  });
});
