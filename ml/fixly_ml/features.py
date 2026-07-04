"""Name-level feature extraction for the package-name risk model.

Pure functions, no network — the exported ONNX model must be runnable
anywhere, so every feature derives from the name string plus two small,
shippable artifacts: a benign character-bigram model and a popular-name list.

The Node inference side mirrors this module exactly; FEATURE_NAMES is the
canonical ordering contract (also emitted into name-risk.meta.json).
"""

from __future__ import annotations

import math
from collections import Counter

# Canonical feature order — the contract with the Node feature builder.
FEATURE_NAMES: list[str] = [
    "length",
    "digit_ratio",
    "hyphen_count",
    "dot_count",
    "underscore_count",
    "has_scope",
    "entropy",
    "vowel_ratio",
    "max_consonant_run",
    "bigram_loglik",
    "min_edit_distance_popular",
    "is_edit_distance_1",
    "has_common_affix",
]

_VOWELS = set("aeiou")
_AFFIXES = ("js-", "node-", "lib", "-js", "-node", "-cli", "-api", "-sdk", "-lib", ".js")


def shannon_entropy(s: str) -> float:
    """Character-level Shannon entropy in bits."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def strip_scope(name: str) -> str:
    """Drop a leading @scope/ — squatting operates on the visible tail."""
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[1]
    return name


def max_consonant_run(s: str) -> int:
    run = best = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Damerau-Levenshtein (OSA variant), capped: returns cap+1 when exceeded.

    The cap keeps dataset-scale feature extraction linear — we only care
    whether a name is *near* a popular one, not how far a random name is.
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    m, n = len(a), len(b)
    prev2: list[int] = []
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[n]


class BigramModel:
    """Add-one-smoothed character bigram language model over benign names.

    Scores how "benign-shaped" a name is: legitimate package names share
    n-gram statistics (short english-ish tokens, common separators); spam and
    generated names sit in the tail.
    """

    BOUNDARY = "\x00"

    def __init__(self) -> None:
        self.counts: Counter[tuple[str, str]] = Counter()
        self.context: Counter[str] = Counter()
        self.vocab: set[str] = set()

    def fit(self, names: list[str]) -> "BigramModel":
        for name in names:
            s = self.BOUNDARY + strip_scope(name.lower()) + self.BOUNDARY
            for a, b in zip(s, s[1:]):
                self.counts[(a, b)] += 1
                self.context[a] += 1
                self.vocab.update((a, b))
        return self

    def log_likelihood(self, name: str) -> float:
        """Mean per-bigram log2 probability (length-normalized)."""
        s = self.BOUNDARY + strip_scope(name.lower()) + self.BOUNDARY
        v = max(len(self.vocab), 1)
        total = 0.0
        pairs = 0
        for a, b in zip(s, s[1:]):
            p = (self.counts[(a, b)] + 1) / (self.context[a] + v)
            total += math.log2(p)
            pairs += 1
        return total / pairs if pairs else 0.0

    def to_dict(self) -> dict:
        return {
            "counts": {f"{a}\t{b}": c for (a, b), c in self.counts.items()},
            "context": dict(self.context),
        }


def extract_features(
    name: str, bigram: BigramModel, popular: list[str]
) -> list[float]:
    """Build the feature vector for one package name, in FEATURE_NAMES order."""
    tail = strip_scope(name.lower())
    n = max(len(tail), 1)

    min_dist = 4  # cap+1 sentinel
    for pop in popular:
        d = edit_distance(tail, strip_scope(pop.lower()))
        if d < min_dist and d > 0:
            min_dist = d
        if min_dist == 1:
            break

    return [
        float(len(tail)),
        sum(ch.isdigit() for ch in tail) / n,
        float(tail.count("-")),
        float(tail.count(".")),
        float(tail.count("_")),
        1.0 if name.startswith("@") else 0.0,
        shannon_entropy(tail),
        sum(ch in _VOWELS for ch in tail) / n,
        float(max_consonant_run(tail)),
        bigram.log_likelihood(name),
        float(min_dist),
        1.0 if min_dist == 1 else 0.0,
        1.0 if any(tail.startswith(a) or tail.endswith(a) for a in _AFFIXES) else 0.0,
    ]
