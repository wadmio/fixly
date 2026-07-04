import { describe, it, expect } from "vitest";
import { buildNameFeatures } from "../src/name-model";

// The feature builder is pure and must mirror ml/fixly_ml/features.py exactly.
// These pin the values the Python side also pins (tests/test_features.py), so
// train/inference drift breaks loudly in CI without needing the ONNX runtime.

const META = {
  feature_names: [
    "length", "digit_ratio", "hyphen_count", "dot_count", "underscore_count",
    "has_scope", "entropy", "vowel_ratio", "max_consonant_run", "bigram_loglik",
    "min_edit_distance_popular", "is_edit_distance_1", "has_common_affix",
  ],
  threshold: 0.5,
  popular: ["lodash", "react", "express"],
  bigram: { counts: { "l\to": 3, "o\td": 2 }, context: { l: 3, o: 5 } },
};

describe("buildNameFeatures (must mirror features.py)", () => {
  it("produces a vector of the declared length", () => {
    const v = buildNameFeatures("lodash", META);
    expect(v).toHaveLength(META.feature_names.length);
  });

  it("measures length on the scope-stripped tail and flags the scope", () => {
    const v = buildNameFeatures("@myorg/pkg", META);
    expect(v[META.feature_names.indexOf("length")]).toBe(3);
    expect(v[META.feature_names.indexOf("has_scope")]).toBe(1);
  });

  it("lights up the edit-distance features for a one-char typo", () => {
    const v = buildNameFeatures("lodahs", META);
    expect(v[META.feature_names.indexOf("min_edit_distance_popular")]).toBe(1);
    expect(v[META.feature_names.indexOf("is_edit_distance_1")]).toBe(1);
  });

  it("counts separators and computes ratios", () => {
    const v = buildNameFeatures("a-b-c", META);
    expect(v[META.feature_names.indexOf("hyphen_count")]).toBe(2);
    // 'a','b','c' are all consonants here? no — 'a' is a vowel. tail length 5.
    expect(v[META.feature_names.indexOf("vowel_ratio")]).toBeCloseTo(1 / 5);
  });

  it("detects a common affix", () => {
    expect(buildNameFeatures("foo-js", META)[META.feature_names.indexOf("has_common_affix")]).toBe(1);
    expect(buildNameFeatures("plainname", META)[META.feature_names.indexOf("has_common_affix")]).toBe(0);
  });
});
