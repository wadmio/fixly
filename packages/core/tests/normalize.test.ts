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

  it("falls back to unknown when no severity data is present", () => {
    const v = normalizeOne({ id: "GHSA-4" });
    expect(v.severity).toBe("unknown");
    expect(v.cvssScore).toBeNull();
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
});
