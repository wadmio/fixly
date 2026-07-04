"""Train the package-name risk model, evaluate it honestly, export to ONNX.

Outputs to ml/models/:
  - name-risk.onnx        the classifier (float32 input, [n,13] -> P(malicious))
  - name-risk.meta.json   feature order, benign bigram model, popular list,
                          decision threshold, and eval metrics
The Node side loads BOTH: the ONNX graph for the estimator, the meta for the
feature builder (which must reproduce features.py exactly).
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import average_precision_score, precision_recall_curve

from .dataset import build
from .features import FEATURE_NAMES, BigramModel, extract_features

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def _pick_threshold(y_true: np.ndarray, scores: np.ndarray, min_precision: float) -> float:
    """Lowest threshold that still meets a precision floor (favor few false
    positives — a noisy name-risk signal erodes trust fast)."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    best = 0.9
    for p, t in zip(precision[:-1], thresholds):
        if p >= min_precision:
            best = float(t)
            break
    return best


def main(min_precision: float = 0.97, max_per_class: int = 6000) -> None:
    corpus = build()
    malicious, benign = corpus["malicious"], corpus["benign"]

    # OSV lists ~215k malicious names — far more than benign, and an unrealistic
    # 99% base rate. Subsample to roughly balance the classes (deterministic),
    # which also keeps the O(names × popular) edit-distance features fast.
    rng = np.random.default_rng(42)
    if len(malicious) > max_per_class:
        idx = rng.choice(len(malicious), size=max_per_class, replace=False)
        malicious = [malicious[i] for i in sorted(idx)]
    if len(benign) > max_per_class:
        idx = rng.choice(len(benign), size=max_per_class, replace=False)
        benign = [benign[i] for i in sorted(idx)]

    bigram = BigramModel().fit(benign)
    # Bounded reference set for the nearest-popular edit-distance feature. This
    # exact list is stored in meta.json; Node iterates it per package check, so
    # keep it small (proximity to a few hundred popular names is enough signal).
    popular_ref = sorted(benign, key=len)[:1200]

    names = malicious + benign
    y = np.array([1] * len(malicious) + [0] * len(benign), dtype=np.int64)
    X = np.array(
        [extract_features(n, bigram, popular_ref) for n in names], dtype=np.float32
    )

    strat = y if min(np.bincount(y)) >= 2 else None
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=strat
    )

    # A small MLP over standardized features: captures nonlinear interaction
    # between entropy, edit-distance and bigram-likelihood (a linear model
    # can't), and exports to ONNX cleanly across versions (tree ensembles
    # currently hit a skl2onnx/onnx converter bug). StandardScaler is part of
    # the pipeline, so it's baked into the exported graph — Node feeds raw
    # features and the ONNX model scales them.
    clf = make_pipeline(
        StandardScaler(),
        MLPClassifier(
            hidden_layer_sizes=(32, 16), alpha=1e-3, max_iter=1500,
            early_stopping=True, n_iter_no_change=25, random_state=42,
        ),
    )
    clf.fit(X_tr, y_tr)

    scores = clf.predict_proba(X_te)[:, 1]
    ap = float(average_precision_score(y_te, scores)) if len(set(y_te)) > 1 else float("nan")
    threshold = _pick_threshold(y_te, scores, min_precision)
    flagged = scores >= threshold
    tp = int(((flagged) & (y_te == 1)).sum())
    fp = int(((flagged) & (y_te == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / int((y_te == 1).sum()) if (y_te == 1).sum() else 0.0

    print(f"[train] source={corpus['source']}  n={len(names)}")
    print(f"[train] average precision (PR-AUC): {ap:.3f}")
    print(f"[train] threshold {threshold:.3f} -> precision {precision:.3f}, recall {recall:.3f}")

    MODELS_DIR.mkdir(exist_ok=True)
    _export_onnx(clf, MODELS_DIR / "name-risk.onnx")

    meta = {
        "feature_names": FEATURE_NAMES,
        "threshold": threshold,
        "popular": popular_ref,
        "bigram": bigram.to_dict(),
        "metrics": {
            "average_precision": ap,
            "precision_at_threshold": precision,
            "recall_at_threshold": recall,
            "n_train": int(len(X_tr)),
            "n_test": int(len(X_te)),
            "source": corpus["source"],
        },
        "note": (
            "Name-only signal. One input to the verdict engine, not a verdict. "
            "The Node feature builder must reproduce fixly_ml.features exactly."
        ),
    }
    (MODELS_DIR / "name-risk.meta.json").write_text(json.dumps(meta, indent=2))
    print(f"[train] wrote {MODELS_DIR / 'name-risk.onnx'} and name-risk.meta.json")


def _export_onnx(clf, path: Path) -> None:
    from skl2onnx import to_onnx

    n_features = len(FEATURE_NAMES)
    sample = np.zeros((1, n_features), dtype=np.float32)
    onx = to_onnx(clf, sample, options={"zipmap": False})
    path.write_bytes(onx.SerializeToString())


if __name__ == "__main__":
    main()
