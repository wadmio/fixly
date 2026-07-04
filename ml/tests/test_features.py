"""Feature-extraction tests — these pin the numbers the Node side must match."""

import math

from fixly_ml.features import (
    FEATURE_NAMES,
    BigramModel,
    edit_distance,
    extract_features,
    max_consonant_run,
    shannon_entropy,
    strip_scope,
)


def test_strip_scope():
    assert strip_scope("@scope/pkg") == "pkg"
    assert strip_scope("lodash") == "lodash"


def test_shannon_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert math.isclose(shannon_entropy("ab"), 1.0)


def test_edit_distance_with_cap():
    assert edit_distance("lodash", "lodahs") == 1  # transposition
    assert edit_distance("lodash", "lodash") == 0
    assert edit_distance("react", "vue") == 4  # exceeds cap 3 -> cap+1


def test_max_consonant_run():
    assert max_consonant_run("lodash") == 2  # "sh" at the end
    assert max_consonant_run("aeiou") == 0
    assert max_consonant_run("strength") == 4  # "ngth"


def test_feature_vector_shape_and_order():
    bigram = BigramModel().fit(["lodash", "react", "express"])
    vec = extract_features("lodash", bigram, ["lodash", "react"])
    assert len(vec) == len(FEATURE_NAMES)
    # length feature is first and correct
    assert vec[FEATURE_NAMES.index("length")] == 6.0
    # has_scope is 0 for an unscoped name
    assert vec[FEATURE_NAMES.index("has_scope")] == 0.0


def test_typosquat_lights_up_edit_distance_features():
    bigram = BigramModel().fit(["lodash"])
    vec = extract_features("lodahs", bigram, ["lodash"])
    assert vec[FEATURE_NAMES.index("min_edit_distance_popular")] == 1.0
    assert vec[FEATURE_NAMES.index("is_edit_distance_1")] == 1.0


def test_scope_flag_and_ignores_scope_for_tail_features():
    bigram = BigramModel().fit(["pkg"])
    scoped = extract_features("@myorg/pkg", bigram, ["pkg"])
    assert scoped[FEATURE_NAMES.index("has_scope")] == 1.0
    # length is measured on the tail, not the scope
    assert scoped[FEATURE_NAMES.index("length")] == 3.0


def test_bigram_prefers_benign_shaped_names():
    bigram = BigramModel().fit(["lodash", "react", "express", "chalk", "commander"])
    benign_like = bigram.log_likelihood("lodish")
    garbage = bigram.log_likelihood("xq7zzk9v")
    assert benign_like > garbage
