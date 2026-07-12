import { describe, it, expect } from "vitest";
import {
  findingKey,
  compareFindingKeys,
  countBySeverity,
  snapshotFindings,
  diffFindingSnapshot,
} from "../src/compare";

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

describe("snapshotFindings / diffFindingSnapshot", () => {
  const finding = (over: Partial<{ package: string; osvId: string; knownExploited: boolean }> = {}) => ({
    package: "lodash",
    osvId: "GHSA-1",
    knownExploited: false,
    ...over,
  });

  it("snapshots knownExploited per finding key", () => {
    expect(snapshotFindings([finding({ knownExploited: true })])).toEqual({
      "lodash::GHSA-1": { knownExploited: true },
    });
  });

  it("classifies added findings and resolved keys", () => {
    const prev = snapshotFindings([finding()]);
    const diff = diffFindingSnapshot(prev, [finding({ package: "minimist", osvId: "GHSA-2" })]);
    expect(diff.added.map((v) => v.package)).toEqual(["minimist"]);
    expect(diff.escalated).toEqual([]);
    expect(diff.resolvedKeys).toEqual(["lodash::GHSA-1"]);
  });

  it("detects a KEV escalation on a carried-over finding (same key)", () => {
    const prev = snapshotFindings([finding()]);
    const diff = diffFindingSnapshot(prev, [finding({ knownExploited: true })]);
    expect(diff.added).toEqual([]);
    expect(diff.escalated.map((v) => v.osvId)).toEqual(["GHSA-1"]);
  });

  it("does not re-escalate an already known-exploited finding", () => {
    const prev = snapshotFindings([finding({ knownExploited: true })]);
    const diff = diffFindingSnapshot(prev, [finding({ knownExploited: true })]);
    expect(diff.escalated).toEqual([]);
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
