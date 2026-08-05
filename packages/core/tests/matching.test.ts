import { describe, it, expect } from "vitest";
import {
  compareSemver,
  isVersionInOsvRanges,
  formatAffectedRanges,
  satisfiesRange,
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

describe("satisfiesRange", () => {
  it("handles caret ranges, including the 0.x special cases", () => {
    expect(satisfiesRange("1.5.0", "^1.2.3")).toBe(true);
    expect(satisfiesRange("2.0.0", "^1.2.3")).toBe(false);
    expect(satisfiesRange("1.2.2", "^1.2.3")).toBe(false);
    expect(satisfiesRange("0.2.9", "^0.2.3")).toBe(true);
    expect(satisfiesRange("0.3.0", "^0.2.3")).toBe(false); // 0.x: minor is breaking
    expect(satisfiesRange("0.0.4", "^0.0.3")).toBe(false); // 0.0.x: patch is breaking
  });

  it("handles tilde ranges", () => {
    expect(satisfiesRange("1.2.9", "~1.2.3")).toBe(true);
    expect(satisfiesRange("1.3.0", "~1.2.3")).toBe(false);
    expect(satisfiesRange("1.9.0", "~1")).toBe(true);
    expect(satisfiesRange("2.0.0", "~1")).toBe(false);
  });

  it("handles comparators, including npm's partial-version semantics", () => {
    expect(satisfiesRange("2.0.0", ">=1.0.0 <3.0.0")).toBe(true);
    expect(satisfiesRange("3.0.0", ">=1.0.0 <3.0.0")).toBe(false);
    expect(satisfiesRange("1.2.5", ">1.2")).toBe(false); // >1.2 means >=1.3.0
    expect(satisfiesRange("1.3.0", ">1.2")).toBe(true);
    expect(satisfiesRange("1.2.5", "<=1.2")).toBe(true); // <=1.2 means <1.3.0
    expect(satisfiesRange("1.3.0", "<=1.2")).toBe(false);
  });

  it("handles exact versions, x-ranges, and stars", () => {
    expect(satisfiesRange("1.2.3", "1.2.3")).toBe(true);
    expect(satisfiesRange("1.2.4", "1.2.3")).toBe(false);
    expect(satisfiesRange("1.9.0", "1.x")).toBe(true);
    expect(satisfiesRange("2.0.0", "1.x")).toBe(false);
    expect(satisfiesRange("1.2.9", "1.2")).toBe(true);
    expect(satisfiesRange("9.9.9", "*")).toBe(true);
    expect(satisfiesRange("9.9.9", "")).toBe(true); // empty range = any version
  });

  it("handles hyphen ranges and || unions", () => {
    expect(satisfiesRange("1.5.0", "1.2.3 - 2.0.0")).toBe(true);
    expect(satisfiesRange("2.0.0", "1.2.3 - 2.0.0")).toBe(true); // inclusive upper
    expect(satisfiesRange("2.0.1", "1.2.3 - 2.0.0")).toBe(false);
    expect(satisfiesRange("2.3.9", "1.2 - 2.3")).toBe(true); // partial upper: <2.4.0
    expect(satisfiesRange("3.0.0", "^1.0.0 || ^3.0.0")).toBe(true);
    expect(satisfiesRange("2.0.0", "^1.0.0 || ^3.0.0")).toBe(false);
  });

  it("returns null for specifiers it cannot evaluate — never a match or a block", () => {
    expect(satisfiesRange("1.0.0", "latest")).toBeNull();
    expect(satisfiesRange("1.0.0", "git+https://github.com/a/b")).toBeNull();
    expect(satisfiesRange("1.0.0", "npm:other-pkg@^1.0.0")).toBeNull();
    expect(satisfiesRange("1.0.0", "workspace:*")).toBeNull();
    expect(satisfiesRange("not-a-version", "^1.0.0")).toBeNull();
  });

  it("a matching alternative wins even when another alternative is unparseable", () => {
    expect(satisfiesRange("1.5.0", "weird-tag || ^1.0.0")).toBe(true);
    expect(satisfiesRange("9.0.0", "weird-tag || ^1.0.0")).toBeNull();
  });

  it("evaluates the >=X <Y strings produced by formatAffectedRanges", () => {
    expect(satisfiesRange("4.17.11", ">=0 <4.17.12")).toBe(true);
    expect(satisfiesRange("4.17.12", ">=0 <4.17.12")).toBe(false);
    expect(satisfiesRange("2.5.0", "<=2.6.6")).toBe(true);
    expect(satisfiesRange("1.5.0", ">=1.0.0")).toBe(true);
  });
});
