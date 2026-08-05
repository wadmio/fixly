# Fixly — developer handoff

Written 2026-08-05 against commit `b8ff4bd` (branch `main`, in sync with
`origin/main` at <https://github.com/wadmio/fixly>). Every claim below was
verified against the code or by running the tooling; anything unverifiable is
marked **UNCERTAIN**.

---

## 1. What Fixly is

Fixly scans a project's npm dependencies — direct **and transitive**, from the
full `package-lock.json` tree — against the **OSV** database, enriches findings
with NVD CVSS and exploit intelligence (CISA KEV, EPSS, public PoC counts), and
computes deterministic **remediation intelligence**: for each vulnerable
package, the minimum safe target version checked against every dependent's
declared version range, the resolution path, the semver jump size, the risk, and
a plain-English rationale. **Fixly analyzes and verifies, never modifies.** It
used to apply fixes — an extension "Apply Remediation Plan" flow with a diff
preview, a CLI `--write` flag, and a core `applyRemediationPlan()` — and all of
that was deliberately removed in v0.2.0 (commits `c2bb964`, `6b51cf3`,
`5bb8f4d`). The reasoning: editing a `package.json` is the easy part that any
coding agent can already do, while *knowing which version is actually safe and
installable given the real dependency graph* is the part that requires the
lock-file analysis Fixly does. Being the ground truth an AI or a teammate acts
on is the differentiator; being one more thing that writes to your manifest is
not. Fixly hands over precise advice and then verifies the outcome on the next
scan.

Context: this is a student capstone. Keep it tight; prefer clarity over
completeness.

---

## 2. Architecture map

pnpm + Turborepo monorepo. Internal packages export **TypeScript source** (no
build step); consumers transpile.

```
packages/core   @fixly/core    the scanner + all analysis. No React/DOM/Next
                               imports — it must run in the Next server AND the
                               VS Code extension host.
packages/ui     @fixly/ui      shared React Badge + severity colors.
apps/web        @fixly/web     Next.js 16 App Router — scans public GitHub repos.
apps/cli        fixly-cli      bin `fixly`: vibecheck, scan, check, guard, fix, watch.
apps/extension  fixly-vscode   VS Code extension (the packaged surface).
apps/mcp        fixly-mcp      MCP stdio server for AI agents.
ml/             (not a workspace package) Python lab; trains the ONNX name-risk model.
```

### How a scan flows, end to end

1. **Read manifests.** Extension: `apps/extension/src/scanner.ts` reads the
   workspace `package.json` + `package-lock.json`. Web: `runScan(repoUrl)`
   fetches them from GitHub. CLI: `apps/cli/src/local.ts` reads from disk.
2. **Parse dependencies** — `packages/core/src/parse-packages.ts` produces
   direct entries plus every unique transitive `name@version` in the lock tree.
3. **Build the dependency graph** — `packages/core/src/lock-graph.ts`
   `buildDependencyGraph(lock)` turns a v2/v3 lock's `packages` map into nodes
   that know who requires whom and with what range. Returns `null` for v1 or
   absent locks. *(Currently only the extension does this step — see §5.)*
4. **Query OSV** — `osv.ts` batches `name@version` pairs; **OSV is the sole
   detection source**.
5. **Normalize** — `normalize.ts` maps OSV records to `ScanVulnerability`
   (severity resolution, fixed version, `MAL-` → `malicious: true`).
6. **Enrich** — `nvd.ts` adds a second CVSS opinion per CVE (best-effort,
   rate-limited); `intel.ts` stamps KEV / EPSS / PoC counts.
7. **Plan remediation** — `remediate.ts` `buildRemediationPlan(result, {graph})`
   groups findings per package and asks the resolution engine what to do.
8. **Render** on each surface.

### Key modules, one line each

| Module | What it owns |
|---|---|
| `packages/core/src/resolution.ts` | The resolution engine: `resolveRemediation(findings, graph)` → resolution path, minimum safe target version, semver distance, risk, rationale. Pure; no network, no fs. |
| `packages/core/src/lock-graph.ts` | Builds the dependency graph from a v2/v3 lock; `dependentsOf(name, version)` resolves edges with npm's nearest-`node_modules` rule. |
| `packages/core/src/matching.ts` | Semver comparison, OSV range evaluation, and `satisfiesRange()` — a dependency-free npm-range subset that returns `null` for anything it cannot evaluate. |
| `packages/core/src/remediate.ts` | Turns a scan into an ordered, **advice-only** plan: actions (upgrade / override / remove), `blocked`, `unfixable`, and the Grade Forecast. |
| `packages/core/src/grade.ts` | The A–F Fixly Score — deterministic point arithmetic; the forecast is literally this function re-run on the scan minus fixed findings. |
| `apps/extension/src/advice.ts` | **vscode-free** — converts a plan into per-package diagnostic tier, one-line message, and hover markdown. Unit-testable without VS Code. |
| `apps/extension/src/diagnostics.ts` | Locates each dependency's line in `package.json` and emits `vscode.Diagnostic` objects from `advice.ts` output. |
| `apps/extension/src/hover.ts` | Serves the hover card when the cursor is on a vulnerable dependency key. |
| `apps/extension/src/panel-render.ts` | **vscode-free** HTML for the webview report (score, forecast, Remediation Plan, findings table). Where most extension tests point. |
| `apps/cli/src/commands/fix.ts` | Prints the plan + forecast as copy-paste advice. |

---

## 3. Current feature state

### SHIPPED — working, tested, ready to publish as 0.2.0

Verified present in code and covered by passing tests:

- **Scanning**: direct + transitive via OSV, NVD CVSS enrichment, KEV/EPSS/PoC
  intel, warnings for partial coverage.
- **Verdict engine** (`checkPackage`): SAFE / CAUTION / BLOCK, backed by
  registry health, typosquat detection, malware records, and an optional ONNX
  name-risk model.
- **Fixly Score** (A–F) with Grade Forecast.
- **Resolution engine + lock graph**: four resolution paths, graph-checked
  target versions, semver distance, risk classification.
- **Extension**: report panel with the Remediation Plan section (risk chips,
  rationale, commands, Blocked card, unfixable list), risk-aware diagnostics,
  hover cards, status bar, on-save / on-type / lock-file-watcher rescans.
- **CLI**: `vibecheck`, `scan` (`--json` / `--sarif` / `--fail-on`), `check`,
  `guard`, `fix` (advice-only), `watch`.
- **MCP server**: `check_package`, `scan_project`, `suggest_safe_alternative`.
- **Web**: scan form, results page, remediation card, localStorage history.

**Publishing status is UNCERTAIN.** `apps/extension/package.json` says `0.2.0`;
git history shows prior versions 0.1.0 → 0.1.2 → 0.1.3, and a commit states the
extension ships on the Marketplace. But **0.2.0 has never been packaged or
published from this working tree**, there are **no git tags**, and I could not
query the Marketplace to confirm which version is live. Assume the published
version is older than this repo and check the Marketplace before publishing.

### BUILT BUT UNVERIFIED — exists and unit-tested, never exercised live

**Nothing in this section has been run inside a real VS Code Extension
Development Host.** The last hands-on F5 session predates the v0.2.0 work.

- **Risk-aware diagnostics + hover cards** (`advice.ts`, `hover.ts`,
  `diagnostics.ts`). 13 unit tests pass, but no one has hovered a real
  dependency and looked at the card. Check: markdown rendering, whether hover
  ranges land correctly on scoped names like `@scope/pkg`, and that the card
  isn't unreadably long for a package with many advisories.
- **Panel Remediation Plan section** — asserted by string matching in tests;
  never seen rendered in an actual webview. Check layout and chip colors.
- **`BLOCKED_BY_PARENT` on a real project** — only ever produced from synthetic
  lock fixtures in tests. Needs a real repo where a parent's range genuinely
  forbids the fix.
- **`lock-graph.ts` against a large real lock file** — tested on a hand-written
  9-entry fixture; never run against a lock with thousands of nested entries.
  Watch for both correctness and performance (`dependentsOf` scans all nodes per
  call, so a plan over many packages is O(packages × nodes) — fine at fixture
  scale, unmeasured at real scale).
- **The 0.2.0 VSIX** — never packaged or installed.

### PLANNED, NOT STARTED

Two phases were designed and approved but never implemented. Summarized here so
you don't need the originating chat.

**Phase 2 — "Copy fix brief".** A new pure module `apps/extension/src/brief.ts`
exporting `buildFixBrief(result, plan)` (all findings) and
`buildPackageBrief(...)` (one package), producing deterministic, paste-ready
text: package name, installed version, minimum safe target, resolution path,
the exact `overrides` JSON when transitive, explicit statements for blocked and
no-fix cases, and a closing "then run npm install and rescan to verify". The
point is to hand an AI agent or a teammate exact ground truth instead of letting
them guess versions. Surfaces: a lightbulb code action on each Fixly diagnostic
("Fixly: copy fix brief for lodash"), a `fixly.copyFixBrief` command for the
whole scan, and a panel button. Clipboard only — Fixly still edits nothing.
Tests go on the pure builder. Note the code-action provider registration was
deleted with `quickfix.ts`; you'll re-add a provider that only copies text.

**Phase 3 — finding-level verification.** After any external change to
`package-lock.json`, the existing watcher already rescans. Compare the previous
scan's finding keys to the new ones with `compareFindingKeys` from
`packages/core/src/compare.ts` and label each: `VERIFIED_RESOLVED` (resolved),
`STILL_PRESENT` (unchanged), `NEW_FINDING_INTRODUCED` (added). Show a short
delta summary — "3 resolved, 1 still present, 1 new" — in the output channel and
one toast. **Reuse the existing watcher**; do not add a second one. The
`lockChanged` flag is already plumbed through `scheduleRescan` → `RunScanOpts` →
`runScan` in `extension.ts` and is currently unused — that is the hook. No new
core code should be needed. (An earlier action-based `verifyRemediation()` in
core was deleted with the apply flow; phase 3 is deliberately finding-level, not
action-level, because advice-only means any external change is verifiable.)

---

## 4. Invariants — do not "fix" these

| Invariant | Why |
|---|---|
| **No surface edits files or runs installs.** Not the extension, not the CLI, not core. | This is the product's positioning, not an oversight. Advice + verification is the differentiator; re-adding an apply flow undoes the v0.2.0 pivot. |
| **No auth, no server persistence.** Scan history is browser localStorage only. | Capstone scope. Adding a backend means accounts, storage, and privacy questions the project deliberately avoids. |
| **No CI/CD gating.** | Same reason. The CLI *offers* `--fail-on` for someone else's CI; the repo doesn't gate on it. |
| **`BLOCKED_BY_PARENT` and `NO_FIX_AVAILABLE` are legitimate states, not errors.** | They're honest answers. Rendering them as failures pushes users toward forcing an untested version, which is exactly the harm the analysis exists to prevent. |
| **Diagnostic severity = fix risk + CVSS, not CVSS alone.** | A low-CVSS finding whose only fix is a major bump deserves attention *because acting on it is consequential*; a high-CVSS finding with a clean patch is a smaller decision. See `diagnosticTier()` in `advice.ts`. |
| **Partial NVD coverage is expected.** | NVD is rate-limited and only *enriches* findings that carry a CVE; it never detects. A scan reporting partial coverage in a warning is correct behavior. |
| **OSV is the only detection source.** | Keeps provenance honest — `ScanResult.source` is `"osv"` or `"osv+nvd"`. |
| **Never invent a version.** Unresolvable specifiers are skipped and warned about; unparseable dependent ranges are "unknown" and never block. | A fabricated version is worse than no answer. `satisfiesRange()` returns `null` rather than guessing. |
| **npm only; transitive analysis requires `package-lock.json`.** | yarn/pnpm locks aren't parsed. No lock file → direct-only + a warning. That's correct, not a bug. |
| **pnpm only for this repo.** | There's no `package-lock.json` here; npm/yarn would create a conflicting lock file. |

---

## 5. Known issues, rough edges, and debt

Verified, not speculative:

1. **Only the extension passes the dependency graph.** `apps/cli/src/commands/fix.ts:34`,
   `apps/cli/src/commands/watch.ts:63`, and
   `apps/web/app/dashboard/results/page.tsx:137` all call
   `buildRemediationPlan(result)` with no graph — so the CLI and web **never
   produce `BLOCKED_BY_PARENT`** and never check dependent constraints. Not a
   crash; a silent capability gap. Fixing it means calling
   `buildDependencyGraph(lock)` in those paths.
2. **The web remediation card doesn't render `plan.blocked`.**
   `apps/web/components/RemediationPlanCard.tsx` handles `unfixable` but has no
   `blocked` branch. Harmless today (see #1), but blocked findings would vanish
   silently the moment web starts passing a graph. Fix both together.
3. **`fixly fix` has a misleading error message.** `fix` accepts a directory
   only, but pointing it at a GitHub URL prints "…point fixly at an npm project
   (or pass a GitHub URL)" — inherited from the shared local-scan path. Either
   support URLs in `fix` or reword the message.
4. **Version numbers are inconsistent and untagged.** Extension `0.2.0`, root
   `package.json` `0.1.0`, and the CLI's `VERSION` constant in
   `apps/cli/src/cli.ts:20` hard-coded to `"0.1.0"` (it does not read
   `package.json`). No git tags exist for any release.
5. **Hover/diagnostic data can be stale between scans.** Both render from the
   last completed scan. Hover *ranges* are re-matched against the live document,
   so they don't drift, but the *content* can describe a version you just
   changed until the debounced rescan lands (1.2s after save, or 1.5s while
   typing with `fixly.scanOnType`). Acceptable, but confusing in a demo.
6. **Transitive findings have no `package.json` line**, so they get no squiggle
   and no hover — they appear only in the report panel and status bar. That's
   deliberate (there's nothing to point at), but it means the majority of
   findings on a real project are invisible in the editor gutter. On NodeGoat,
   1055 of 1091 packages are transitive.
7. **`dependentsOf` is unindexed** — it iterates every graph node per call. See
   the performance note in §3.
8. **`onnxruntime-node` is an optional dependency.** If it fails to install on a
   given platform, `scoreNameRisk()` returns `null` and the verdict engine
   falls back to rule-based typosquat detection. Silent degradation by design —
   but if name-risk signals seem missing, check this first.
9. **Web tests run in Vitest's node environment**, not jsdom — full React DOM
   rendering is broken in this toolchain (react/react-dom dual-instance), so
   scan-page coverage is module-load and URL-gate logic only. Use Playwright if
   you need real page rendering.
10. **`DEMO_CHANGES.md` is stale by design** — it documents the now-removed
    apply flow and carries a "superseded" banner. Historical record; don't trust
    it as current.

**Clean findings** (I checked, and it's genuinely clean): no `TODO`, `FIXME`,
`HACK`, or `XXX` markers anywhere in `apps/`, `packages/`, or `scripts/`; no
skipped, `.only`, or `.todo` tests in any suite.

---

## 6. Dev setup on a fresh machine

**Prerequisites:** Node 20 (`.nvmrc` pins it) and pnpm (`packageManager` pins
`pnpm@10.11.1`). Nothing else — no database, no accounts, no API keys.

```bash
git clone https://github.com/wadmio/fixly.git
cd fixly
pnpm install          # pnpm ONLY — npm/yarn will create a conflicting lock file
pnpm build            # 4 build tasks: web, extension, cli, mcp
pnpm test             # expect: 5 tasks, 231 tests, all passing
pnpm typecheck        # expect: 6 tasks, all passing
pnpm lint
```

**Test counts as of `b8ff4bd`** (run 2026-08-05, all passing):

| Package | Tests |
|---|---|
| `@fixly/core` | 161 |
| `fixly-cli` | 30 |
| `fixly-vscode` | 27 |
| `@fixly/web` | 8 |
| `fixly-mcp` | 5 |
| **Total** | **231** |

Scope work with `--filter`, e.g. `pnpm --filter @fixly/core test`, or a single
file: `pnpm --filter @fixly/core exec vitest run tests/resolution.test.ts`.

**Web app:** `pnpm dev` → <http://localhost:3000> → dashboard → paste a public
GitHub repo URL.

**Extension (F5 debug flow):**

```bash
pnpm --filter fixly-vscode build     # required — F5 launches from dist/
```

Open the **`apps/extension`** folder in VS Code (not the repo root) and press
<kbd>F5</kbd>. That uses the **Run Fixly Extension** config in
`apps/extension/.vscode/launch.json` to open an Extension Development Host. In
that window, open a Node project folder and run **Fixly: Scan Current Project**
from the command palette. Logs go to the "Fixly" output channel.

**Running against a fixture project.** Fixly needs an **npm** project with both
`package.json` and `package-lock.json`. This repo is a pnpm workspace, so
pointing Fixly at itself yields direct-only results plus a warning — don't use
it as your fixture. Create one:

```bash
mkdir -p /tmp/fixly-fixture && cd /tmp/fixly-fixture
npm init -y && npm install lodash@4.17.4 minimist@1.2.0   # both have known advisories
node <repo>/apps/cli/dist/cli.js vibecheck .
```

**NodeGoat caveat.** `https://github.com/OWASP/NodeGoat` is the usual demo
target — deliberately vulnerable and good for exercising the risky paths. I
scanned it to check the numbers: **289 findings across 1091 packages** (36
direct, 1055 transitive), 288 with a published fix, of which **99 (~34%) are
major-version bumps** and 1 has no fix at all. So it is *not* true that nearly
all NodeGoat fixes are major bumps — a third are, which is still plenty to
exercise elevated-risk rendering. What it's genuinely bad for is the **happy
path**: there is no clean or near-clean state to demo, and 1055 transitive
packages make the editor-gutter experience look empty (see §5 item 6). Use a
small hand-built fixture for the calm path.

**Publishing the extension** (needs the `fixly` publisher's Marketplace PAT —
**UNCERTAIN** who holds it; confirm before planning a release):

```bash
pnpm --filter fixly-vscode package:vsix        # → fixly-vscode-<version>.vsix
npx vsce publish --packagePath fixly-vscode-<version>.vsix
```

Local version is `0.2.0`; verify what's actually live on the Marketplace first
(see §3).

---

## 7. Suggested first tasks

1. **Manually verify the v0.2.0 in-editor surfaces** (start here — it's the
   biggest gap between "tested" and "known to work"). Build, F5, open a fixture,
   and look at the squiggles and hover cards. Touches nothing unless you find a
   bug; if you do, it's in `apps/extension/src/advice.ts` (content and tier) or
   `hover.ts` (positioning). Try a scoped package name — that path is untested.
2. **Implement phase 2, "copy fix brief"** (§3). New pure module
   `apps/extension/src/brief.ts` with tests alongside
   `apps/extension/tests/advice.test.ts`; register a code-action provider in
   `extension.ts` (the old registration was removed with `quickfix.ts` — use
   `advice.ts`'s per-package map as the data source) and add a command to
   `apps/extension/package.json`. Self-contained and doesn't touch core.
3. **Pass the dependency graph in the CLI and web** (§5 items 1–2). Call
   `buildDependencyGraph(lock)` in `apps/cli/src/local.ts` consumers and the web
   results page, then add the missing `blocked` branch to
   `RemediationPlanCard.tsx`. Small, high-value: it makes blocked-by-parent
   analysis real on every surface instead of just the extension.

---

## 8. Working on this repo with Claude Code

- **Read [CLAUDE.md](CLAUDE.md) first.** It's the architecture and conventions
  brief Claude Code loads automatically, and it's kept current — it documents
  the pipeline, the module map, and the scope guardrails in more detail than
  this file.
- **Plan-first workflow.** The pattern that has worked here: ask Claude for a
  written plan *before* any code, review and approve it, then have it implement
  in phases and **stop after each phase to check in**. This repo's recent
  resolution-engine work was built that way in four phases. Claude Code has a
  plan mode for exactly this — ask for a plan and it will explore the code and
  propose one rather than editing.
- **Briefs live as markdown files in the repo**, not as pasted prompts. Write
  the requirement down (like this file, or `docs/`), then point Claude at it.
  The brief stays reviewable, diffable, and available to the next person.
- **Ask it to verify, not assert.** The useful habit: "run the tests and record
  the real numbers", "confirm this function exists before describing it". This
  document was produced that way, which is why §6 corrects a NodeGoat
  assumption that turned out to be wrong.
- **Respect the invariants in §4.** If a change would make Fixly write to a
  file, run an install, add a server, or turn a legitimate state into an error,
  it's almost certainly wrong — say so rather than implementing it.
