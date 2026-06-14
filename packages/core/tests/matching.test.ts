import { describe, it, expect } from "vitest";
import {
  compareSemver,
  isVersionInOsvRanges,
  formatAffectedRanges,
} from "../src/matching";
import type { OsvVuln } from "../src/osv";

describe("compareSemver", () => {
  it("orders major/minor/patch numerically", () => {
    expect(compareSemver("1.2.3", "1.2.4")).toBe(-1);
    expect(compareSemver("1.10.0", "1.9.0")).toBe(1);
    expect(compareSemver("2.0.0", "2.0.0")).toBe(0);
  });

  it("treats a pre-release as lower than the release, and tolerates a v prefix", () => {
    expect(compareSemver("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareSemver("v1.2.0", "1.2.0")).toBe(0);
  });

  it("returns null for an unparseable version", () => {
    expect(compareSemver("latest", "1.0.0")).toBeNull();
    expect(compareSemver("1.0.0", "*")).toBeNull();
  });
});

// A realistic OSV record: lodash prototype pollution, affected >=0 <4.17.12.
const lodashVuln: OsvVuln = {
  id: "GHSA-jf85-cpcp-j695",
  aliases: ["CVE-2019-10744"],
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.12" }] }],
    },
  ],
};

describe("isVersionInOsvRanges — known vulnerable vs non-vulnerable", () => {
  it("flags a version inside the affected range as vulnerable", () => {
    expect(isVersionInOsvRanges("4.17.4", lodashVuln, "lodash")).toBe(true);
  });

  it("clears a version at or above the fixed version", () => {
    expect(isVersionInOsvRanges("4.17.12", lodashVuln, "lodash")).toBe(false);
    expect(isVersionInOsvRanges("4.17.21", lodashVuln, "lodash")).toBe(false);
  });

  it("honours an introduced lower bound (not just package name)", () => {
    const v: OsvVuln = {
      id: "X",
      affected: [
        { ranges: [{ type: "SEMVER", events: [{ introduced: "1.5.0" }, { fixed: "1.8.0" }] }] },
      ],
    };
    expect(isVersionInOsvRanges("1.4.0", v)).toBe(false); // below introduced
    expect(isVersionInOsvRanges("1.6.0", v)).toBe(true); // inside
    expect(isVersionInOsvRanges("1.8.0", v)).toBe(false); // at fixed (exclusive)
  });

  it("supports last_affected (inclusive upper bound)", () => {
    const v: OsvVuln = {
      id: "Y",
      affected: [
        { ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { last_affected: "2.6.6" }] }] },
      ],
    };
    expect(isVersionInOsvRanges("2.6.6", v)).toBe(true);
    expect(isVersionInOsvRanges("2.6.7", v)).toBe(false);
  });

  it("matches an explicit affected.versions list", () => {
    const v: OsvVuln = { id: "Z", affected: [{ versions: ["1.0.0", "1.0.1"] }] };
    expect(isVersionInOsvRanges("1.0.1", v)).toBe(true);
    expect(isVersionInOsvRanges("1.0.2", v)).toBe(false);
  });

  it("returns null (limited confidence) when nothing is locally evaluable", () => {
    // No ranges/versions at all → cannot verify locally.
    expect(isVersionInOsvRanges("1.0.0", { id: "no-ranges" })).toBeNull();
    // Unparseable installed version → cannot compare.
    expect(isVersionInOsvRanges("not-a-version", lodashVuln, "lodash")).toBeNull();
  });
});

describe("formatAffectedRanges", () => {
  it("renders an introduced/fixed range, dropping the noisy >=0", () => {
    expect(formatAffectedRanges(lodashVuln, "lodash")).toEqual(["<4.17.12"]);
  });

  it("renders an introduced lower bound and a last_affected upper bound", () => {
    const v: OsvVuln = {
      id: "Q",
      affected: [
        { ranges: [{ type: "SEMVER", events: [{ introduced: "1.2.0" }, { last_affected: "1.9.9" }] }] },
      ],
    };
    expect(formatAffectedRanges(v)).toEqual([">=1.2.0 <=1.9.9"]);
  });
});
