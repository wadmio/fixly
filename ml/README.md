# Fixly ML Lab

Machine-learning signals for the verdict engine. **Training happens here in
Python; inference ships to Node via ONNX** — users of `npx fixly` never need
Python installed.

```
ml/
├── fixly_ml/
│   ├── features.py    name-level feature extraction (pure, no network)
│   ├── dataset.py     builds the labeled corpus from real sources
│   └── train.py       trains, evaluates honestly, exports ONNX
├── tests/             pytest suite for feature extraction
├── data/              downloaded corpora (gitignored)
└── models/            exported ONNX models + feature manifests
```

## Model 1 — package-name risk (`name-risk.onnx`)

**Question it answers:** "does this npm package *name* look like the malicious
population (typosquats, machine-generated spam, slopsquat bait) or like the
legitimate population?"

- **Positive labels:** names from real OSV `MAL-*` advisories (the
  [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages)
  corpus, via the OSV npm dump).
- **Negative labels:** popular real package names collected from the npm
  search API (popularity-weighted).
- **Features:** length/character statistics, Shannon entropy, character-bigram
  log-likelihood under a benign-corpus language model, edit distance to the
  nearest popular package, affix flags. Name-only by design — the exported
  model runs offline, with zero network calls, anywhere.
- **Estimator:** scikit-learn `HistGradientBoostingClassifier` (gradient
  boosting; no GPU, trains in seconds, exports cleanly to ONNX).

### Honest limits (read before believing a metric)

A name-only model cannot catch a well-named malicious package — that is what
the verdict engine's registry/OSV/behavioral signals are for. This model's job
is to be **one more independent signal** (weight it like a smell, not a
verdict), especially for brand-new packages with no history. Class balance in
the wild is extremely skewed; we report precision at high thresholds, not
accuracy.

### Roadmap

- **v2 — behavioral malware classifier:** features from package *tarballs*
  (install-script AST patterns: `child_process`/`eval`/network in preinstall,
  obfuscation entropy, size anomalies), trained on the same OpenSSF corpus.
  This is the model with the real ceiling; the name model ships first because
  it needs no tarball pipeline.
- **v3 — release-anomaly detection:** `IsolationForest` over registry
  time-series (version velocity, maintainer churn) — the "this package just
  got taken over" early warning.

## Run it

```bash
cd ml
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt      # (POSIX: .venv/bin/pip)
.venv\Scripts\python -m fixly_ml.dataset           # downloads + builds corpus
.venv\Scripts\python -m fixly_ml.train             # trains, evaluates, exports ONNX
.venv\Scripts\python -m pytest tests -q            # feature tests
```

Outputs land in `ml/models/`:
- `name-risk.onnx` — the model
- `name-risk.meta.json` — feature order + threshold + eval metrics (the Node
  side MUST build the feature vector in exactly this order)

## Node integration contract

Inference runs in `@fixly/core` behind the verdict engine via
`onnxruntime-node`, loaded lazily and **optional at runtime** — if the model
file or runtime is missing, the engine falls back to the rule-based typosquat
signal with a warning. The TS feature builder must mirror `features.py`
exactly; `name-risk.meta.json` is the source of truth for ordering, and the
pytest suite pins feature values so drift breaks loudly.
