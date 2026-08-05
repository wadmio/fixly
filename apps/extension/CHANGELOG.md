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

### Added

- Risk-aware diagnostics with remediation hover cards in package.json.
- **Copy Fix Brief** — deterministic, paste-ready fix instructions for a
  teammate or AI agent: minimum safe target, resolution path, semver jump,
  risk, rationale, exact `overrides` JSON for transitive pins, and explicit
  blocked / no-fix statements. Available as **Fixly: Copy Complete Fix Brief**,
  a lightbulb code action on each Fixly diagnostic, and a report-panel button.
  Clipboard only — nothing is applied.
- **Post-change verification** — after any external package-lock.json change
  (you or your agent ran npm install), the watcher's rescan classifies every
  finding as VERIFIED_RESOLVED / STILL_PRESENT / NEW_FINDING_INTRODUCED and
  reports one concise summary (toast + output channel).

### Kept

- The full remediation analysis: per-package resolution path, graph-checked
  minimum safe target, semver distance, risk classification, rationale, and
  the Grade Forecast — in the report panel, status bar, and diagnostics.
- On-save and lock-file-watch rescans.

## 0.1.3 and earlier

Scanning (direct + transitive via OSV, NVD cross-reference), Fixly Score,
report panel, inline diagnostics, on-save rescans, and the since-removed
apply-fix flow.
