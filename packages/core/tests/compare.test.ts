import { describe, it, expect } from "vitest";
import { findingKey, compareFindingKeys, countBySeverity } from "../src/compare";

describe("findingKey", () => {
  it("is stable across versions of the same finding", () => {
    expect(findingKey({ package: "lodash", osvId: "GHSA-1" })).toBe("lodash::GHSA-1");
  });
});

describe("compareFindingKeys", () => {
  it("classifies added, resolved, and unchanged findings", () => {
    const prev = ["a::1", "b::2", "c::3"];
    const next = ["b::2", "c::3", "d::4"];
    expect(compareFindingKeys(prev, next)).toEqual({
      added: ["d::4"],
      resolved: ["a::1"],
      unchanged: ["b::2", "c::3"],
    });
  });

  it("handles a first scan (no previous keys)", () => {
    expect(compareFindingKeys([], ["a::1"])).toEqual({
      added: ["a::1"],
      resolved: [],
      unchanged: [],
    });
  });

  it("handles a fully-resolved next scan", () => {
    expect(compareFindingKeys(["a::1"], [])).toEqual({
      added: [],
      resolved: ["a::1"],
      unchanged: [],
    });
  });
});

describe("countBySeverity", () => {
  it("tallies every severity bucket", () => {
    const counts = countBySeverity([
      { severity: "critical" },
      { severity: "critical" },
      { severity: "high" },
      { severity: "unknown" },
    ]);
    expect(counts).toEqual({ critical: 2, high: 1, medium: 0, low: 0, unknown: 1 });
  });
});
