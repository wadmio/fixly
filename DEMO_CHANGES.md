# Demo changes — `feat/extension-remediation-plan`

Everything on this branch vs `main`, for a capstone walkthrough. Scope is taken
strictly from `git diff main...HEAD` (18 files, +663/−66). Five features: three
in the VS Code extension, two in the shared core (`@fixly/core`) that the
extension surfaces.

**Setup (once):**

```bash
pnpm install
pnpm --filter fixly-vscode build          # bundle → apps/extension/dist/extension.js
```

Open `apps/extension` in VS Code and press <kbd>F5</kbd> ("Run Fixly Extension",
from `apps/extension/.vscode/launch.json`) to open an **Extension Development
Host**. In that window open a Node.js project that has a `package.json` **and**
`package-lock.json` with at least one vulnerable dependency, then run
**Fixly: Scan Current Project** from the command palette.

---

## 1. Apply Remediation Plan — one-click fixes with a diff preview

**What it does:** turns the current scan's fix plan into edits to `package.json`
(dependency upgrades + transitive `overrides`), shown as a side-by-side diff you
approve before anything is written.

**Files:**
- `apps/extension/src/apply-plan.ts` (new) — builds the plan, computes the
  proposed `package.json` in memory, opens the diff, asks to confirm, then writes.
- `apps/extension/src/preview.ts` (new) — a `TextDocumentContentProvider` on a
  `fixly-preview:` scheme that serves the proposed file as a read-only virtual
  document (the right-hand side of the diff).
- `apps/extension/src/panel-render.ts` (changed) — adds a **Grade Forecast**
  line and an **Apply Fix Plan** button under the score card.
- `apps/extension/src/panel.ts` (changed) — handles the `applyPlan` webview
  message by running the command.
- `apps/extension/src/extension.ts` (changed) — registers the
  `fixly.applyRemediationPlan` command and the content provider, and appends the
  forecast grade to the status-bar tooltip.
- `apps/extension/package.json` (changed) — contributes the command.

**Core reuse vs extension-only:**
- **From `@fixly/core`:** `buildRemediationPlan(scan)` produces the ordered
  actions + the `GradeForecast` (before/after grade & score); `applyRemediationPlan(text, plan)`
  rewrites the `package.json` text (preserving `^`/`~` style); `computeGrade` is
  what the forecast is built on. The extension computes **nothing** about which
  fixes to apply — it only renders and writes.
- **Extension-only:** the `vscode.diff` preview, the virtual content provider,
  the modal confirmation, and the `WorkspaceEdit` that writes the file. At write
  time it re-reads `package.json` and aborts if it changed since the preview
  (so it never clobbers an edit made during the dialog).

**Trigger live:** run **Fixly: Scan Current Project**, then either click
**Apply Fix Plan** in the report or run **Fixly: Apply Remediation Plan** from
the palette → a diff opens → confirm **Apply**. Malware is never auto-edited: it
shows the `npm uninstall` commands to run by hand. No install is run — finish
with `npm install`.

**Settings:** none. (Command ID `fixly.applyRemediationPlan`.)

---

## 2. As-you-type scanning

**What it does:** with an opt-in setting on, editing `package.json` re-scans from
the **unsaved** editor buffer (no save needed), debounced.

**Files:**
- `apps/extension/src/debounce.ts` (new) — a tiny, framework-free debounce
  (pure, no `vscode` import).
- `apps/extension/tests/debounce.test.ts` (new) — 4 unit tests (fires once after
  the quiet period, coalesces rapid calls to the latest args, `cancel()`,
  re-fires after firing).
- `apps/extension/src/extension.ts` (changed) — an `onDidChangeTextDocument`
  listener (1.5s debounce) plus **coalescing single-flight**: a request arriving
  mid-scan is queued and the freshest one runs when the current scan ends, and a
  scan discards its own results if a newer edit is already pending.
- `apps/extension/src/scanner.ts` (changed) — `scanWorkspace` now accepts an
  optional `packageJsonText`; when set it parses the buffer instead of reading
  `package.json` from disk (invalid mid-edit JSON is skipped quietly).
- `apps/extension/package.json` (changed) — adds the `fixly.scanOnType` setting.

**Core reuse vs extension-only:**
- **From `@fixly/core`:** `scanProjectFiles({ packageJson, packageLock, … })`
  already accepts an **in-memory parsed** `packageJson` object, so no core change
  was needed — the extension just parses the buffer and passes it. The saved
  `package-lock.json` is still read from disk for the dependency tree.
- **Extension-only:** the debounce, the text-change listener, and the
  coalescing/staleness control flow.

**Trigger live:** enable **Fixly: Scan On Type** (`fixly.scanOnType`), edit a
dependency version in `package.json`, and watch the status bar re-scan ~1.5s
after you stop typing — no save.

**Settings:** `fixly.scanOnType` — **default `false`** (new on this branch).

---

## 3. NVD API key setting

**What it does:** lets you paste an NVD API key into a setting so scans get
wider CVE cross-referencing, without touching environment variables.

**Files:**
- `apps/extension/src/scanner.ts` (changed) — reads `fixly.nvdApiKey`; when
  non-empty sets `process.env.NVD_API_KEY` before scanning, and logs a **masked**
  confirmation (last 4 chars only) to the Fixly output channel.
- `apps/extension/package.json` (changed) — adds the `fixly.nvdApiKey` setting.

**Core reuse vs extension-only:**
- **From `@fixly/core`:** `enrichWithNvd` reads `process.env.NVD_API_KEY` at scan
  time; the extension runs core in the same Node process, so setting the env var
  reaches the NVD client exactly like a shell-exported key would.
- **Extension-only:** reading the VS Code setting and masking the key in logs.

**Trigger live:** get a free key at
<https://nvd.nist.gov/developers/request-an-api-key>, set **`fixly.nvdApiKey`**
(prefer VS Code **User** settings so it stays out of the repo), re-scan, and the
report's NVD-coverage warning shows a higher number of covered CVEs.

**Settings:** `fixly.nvdApiKey` — **default `""`** (new on this branch). If blank,
a shell `NVD_API_KEY` is still used.

---

## 4. Concurrent NVD enrichment (core)

**What it does:** when an NVD key is present, cross-reference CVEs **concurrently
under a larger time budget**, so a scan reaches the 40-CVE cap instead of the
~3 the old serial 8-second budget allowed.

**Files:**
- `packages/core/src/nvd.ts` (changed) — with a key: concurrency 8, 15s budget
  (cap 40); without a key: unchanged serial, 8s budget, cap 5. Uses the existing
  `mapWithConcurrency` helper with a per-request budget cap and a deadline; the
  coverage warning no longer tells you to set a key when one is already set.

**Core reuse vs extension-only:** entirely `@fixly/core`. The extension benefits
automatically once a key is set (feature #3). No extension code involved.

**Trigger live:** with `fixly.nvdApiKey` set, scan a project with many CVEs and
compare the report's "NVD cross-check covered N of M" line before/after.

**Settings:** none of its own (gated by whether a key is present).

---

## 5. Transitive malware with a fix → override, not "remove by hand" (core)

**What it does:** a malicious-package advisory that **has a published fix** and
is pulled in **transitively** is now remediated by pinning the tree to the fixed
version (`overrides`), instead of the dead-end "remove it by hand" message.

**Files:**
- `packages/core/src/remediate.ts` (changed) — new `mustRemovePackage()` rule:
  remove only when the malware is **direct** (you can uninstall it) or has **no
  fix**; a transitive malware advisory **with** a fix becomes an `override`.
- `packages/core/tests/remediate.test.ts` (changed) — 3 new tests
  (transitive-malware-with-fix → override, transitive-malware-no-fix → remove,
  direct-malware-with-fix → remove).

**Core reuse vs extension-only:** entirely `@fixly/core`. The extension surfaces
it through the same Apply Remediation Plan flow (feature #1).

**Trigger live:** scan a project whose lockfile pulls in old **fsevents**
(`<1.2.11`, advisory `MAL-2023-462`, fixed in `1.2.11`). The fix plan now offers
`npm pkg set overrides.fsevents=1.2.11 && npm install` and the Apply Remediation
Plan diff writes that `overrides` entry — no more manual-removal dead end.

**Settings:** none.

---

## Docs updated on this branch

`README.md`, `PROJECT_STATUS.md`, `apps/extension/README.md`,
`docs/development.md`, and `CLAUDE.md` were updated to match the above;
`apps/extension/.vscode/launch.json` was committed so the F5 workflow is
reproducible from a clean clone.

---

## Known limitations (honest)

- **`scanOnType` costs live API calls.** Every debounced edit runs a full scan,
  which hits OSV (and NVD when a key is set). That's why it defaults to **off**;
  leaving it on while heavily editing `package.json` makes repeated network
  requests. The debounce (1.5s) and coalescing limit but don't eliminate this.
- **`scanOnType` reads a stale lockfile.** It scans the unsaved `package.json`
  but the saved `package-lock.json`. Direct versions resolve from the lock (or
  the range minimum), so typing a fixed version won't clear a finding until you
  actually `npm install` and the lockfile updates — the live re-scan reflects
  what's installed, not what you just typed.
- **NVD coverage is still partial on big repos.** Even with a key the cap is 40
  CVEs per scan within a 15s budget; a project like NodeGoat (~155 unique CVEs)
  shows partial coverage. Without a key it's 5. Coverage grows across repeated
  scans because the CVE cache warms up. OSV remains the detection source; NVD
  only adds a second CVSS opinion.
- **Apply Remediation Plan never installs.** It writes `package.json` only and by
  design does not run `npm install` or touch `node_modules`; the fix isn't real
  until you install. Transitive `overrides` (e.g. pinning fsevents) are pinned to
  the advisory's fixed version, which can be older than latest and may be
  undesirable for platform-specific packages.
- **Direct malware still needs manual removal.** Only transitive-malware-with-a-fix
  is auto-remediated (override); direct malware and fix-less malware still show
  `npm uninstall` commands to run by hand.
- **Extension scope is unchanged.** npm only, requires a `package.json`
  (transitive scanning requires `package-lock.json`), and it scans the **first**
  workspace folder only.
- **Verification done:** `@fixly/core` typecheck + full suite (131 tests) pass;
  the extension typechecks, builds, and its `debounce` tests pass. There is no
  end-to-end/UI test for the extension host — the diff-preview and apply flow are
  exercised manually in the Extension Development Host.
