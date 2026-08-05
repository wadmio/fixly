# Changelog

## 0.2.0

**Positioning pivot: Fixly analyzes and verifies, never modifies.**

Fixly's value is deterministic, graph-accurate remediation intelligence — the
minimum safe target version computed against your real package-lock.json
dependency graph, the resolution path (direct upgrade / transitive override /
blocked by a parent's range / no fix published), the semver jump size, and a
plain-language rationale. That is ground truth a chat AI guessing at versions
cannot produce. Fixly hands you (or your AI agent) that ground truth and then
verifies the outcome on the next scan — it no longer edits anything.

### Removed

- **Fixly: Apply Remediation Plan** command, the package.json diff-preview +
  confirm edit flow, and the "Run npm install" button. Fixly no longer writes
  to any file or launches any process.
- Quick Fix lightbulb that rewrote dependency version ranges in package.json.

### Kept

- The full remediation analysis: per-package resolution path, graph-checked
  minimum safe target, semver distance, risk classification, rationale, and
  the Grade Forecast — in the report panel, status bar, and diagnostics.
- On-save and lock-file-watch rescans.

### Coming in this release line

- Risk-aware diagnostics with remediation hover cards in package.json.
- "Copy fix brief" — paste-ready fix instructions for a teammate or AI agent.
- Post-change verification: findings marked resolved / still present / newly
  introduced after every external change to the lock file.

## 0.1.3 and earlier

Scanning (direct + transitive via OSV, NVD cross-reference), Fixly Score,
report panel, inline diagnostics, on-save rescans, and the since-removed
apply-fix flow.
