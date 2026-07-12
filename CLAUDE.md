# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> Note: a `CLAUDE.md` for an unrelated project ("Opsidian Voice Agent OS") lives in the parent
> directory (`C:\Users\Diomio\Desktop\CLAUDE.md`) and gets auto-loaded up the tree. It does **not**
> apply to Fixly — ignore its Retell/voice-agent rules here.

## What this is

Fixly scans projects for vulnerable **npm dependencies** — direct **and transitive** (full lock-file tree) — using the **OSV** database, with best-effort **NVD** CVE cross-referencing. A student capstone. It is a **pnpm + Turborepo workspace** with two apps and two shared packages:

```
apps/web         @fixly/web      Next.js 16 (App Router) web scanner — scans public GitHub repos
apps/extension   fixly-vscode    VS Code extension — inline diagnostics, on-save rescan, webview report
apps/cli         fixly-cli       CLI (bin: fixly) — vibecheck (A–F grade), scan (JSON/SARIF/--fail-on), check (verdicts), guard (pre-install check)
apps/mcp         fixly-mcp       MCP server (stdio) — check_package / scan_project / suggest_safe_alternative for AI agents
packages/core    @fixly/core     the scanner: GitHub fetch, parsing, OSV client, NVD enrichment, verdict engine
packages/ui      @fixly/ui       shared React UI (Badge + severity helpers)
```

**OSV is the detection source**; NVD only enriches findings that carry a CVE (`ScanResult.source` is `"osv"` or `"osv+nvd"`). Scope is intentionally tight (see guardrails).

## Commands (run from the repo root)

```bash
pnpm install      # pnpm only — do NOT use npm/yarn (no package-lock.json)
pnpm dev          # turbo: runs the web dev server (http://localhost:3000)
pnpm build        # turbo: next build + esbuild bundle the extension
pnpm lint         # turbo: eslint every package
pnpm typecheck    # turbo: tsc --noEmit every package
pnpm test         # turbo: vitest (packages/core is the main suite + apps/web node-env tests)
```

Scope a task to one package with `--filter`, e.g. `pnpm --filter @fixly/core test`, `pnpm --filter fixly-vscode build`. Run one Vitest file: `pnpm --filter @fixly/core exec vitest run tests/github.test.ts`.

Test the scanner without any UI:
```bash
curl -X POST localhost:3000/api/scan -H "Content-Type: application/json" \
  -d '{"repoUrl":"https://github.com/OWASP/NodeGoat"}'
```

## Architecture

### packages/core (`@fixly/core`) — the scanner, environment-agnostic

Public API in [packages/core/src/index.ts](packages/core/src/index.ts). Pipeline:

1. [github-url.ts](packages/core/src/github-url.ts) `parseGitHubUrl()` — pure URL parsing (`/owner/repo`, `/tree/<branch>/<subpath>`), also exported at `@fixly/core/url` for **client-safe** import (no Node deps). [github.ts](packages/core/src/github.ts) `fetchProject()` — verifies repo + branch via the GitHub REST API and returns a discriminated `FetchResult` with precise error codes; uses an optional **server-side** `GITHUB_TOKEN` (~60→5000 req/hr).
2. [parse-packages.ts](packages/core/src/parse-packages.ts) `parseDependencies(pkgJson, lock, {includeTransitive})` — direct `dependencies` + `devDependencies` → `DependencyEntry[]` (`requestedVersion`, lock-exact `installedVersion`, `dependencyType`, `sourceFile`) **plus every unique transitive `name@version` pair from the lock tree** (v1 recursion / v2-v3 `packages` map incl. nested `node_modules` paths; `dependencyType: "transitive"`, skips `link: true`). Default on; needs a lock file. `resolveCheckVersion()` = lock version ?? range minimum; unresolvable specifiers (`*`, `latest`, npm aliases) are skipped + warned, never invented.
3. [osv.ts](packages/core/src/osv.ts) `queryOsvBatch()` — POST `/querybatch` (ecosystem hardcoded `"npm"`) → GET `/vulns/{id}`. Results are keyed by `osvQueryKey()` (`name@version`) because the same package can be checked at several versions.
4. [normalize.ts](packages/core/src/normalize.ts) `normalizeOsvResults()` — severity priority: `database_specific.severity` → locally-computed **CVSS v3.1 base score** (`cvssV3BaseScore()`) → per-`affected` → `"unknown"`. Stamps `dependencyType`, `sources: ["osv"]`, `nvd: null`.
5. [nvd.ts](packages/core/src/nvd.ts) `enrichWithNvd()` — best-effort NVD CVE cross-reference: 5 fetches/scan without a key, 40 with `NVD_API_KEY`; 4s/request timeout, 8s scan budget, module-level CVE cache, warnings on partial coverage. Fills `nvd: {cvssScore, cvssVector, severity}` + appends `"nvd"` to `sources`. **Never fails a scan.** Disable via `FIXLY_DISABLE_NVD=1` or `scanProjectFiles({nvd: false})`.
6. [compare.ts](packages/core/src/compare.ts) — pure scan-diff helpers (`findingKey` = `package::osvId`, `compareFindingKeys` → added/resolved/unchanged, `countBySeverity`), exported at `@fixly/core/compare` for **client-safe** import.
7. **Verdict engine** (powers `check`/vibecheck/MCP/guard surfaces):
   - [registry.ts](packages/core/src/registry.ts) — npm registry profile (exists/age/downloads/deprecated/install-scripts; tiny `/latest` endpoint for version resolution). 404 = "does not exist" (hallucination signal); network failure THROWS — "couldn't check" is never "safe".
   - [typosquat.ts](packages/core/src/typosquat.ts) + [popular-packages.ts](packages/core/src/popular-packages.ts) — pure-string typosquat/slopsquat detection (Damerau-Levenshtein + affix patterns like `eslint-plugin-` drops) against a curated popular list. A match is a SIGNAL, not a verdict.
   - [intel.ts](packages/core/src/intel.ts) — exploit-intel enrichment stamping `knownExploited`/`kevDateAdded`/`epssScore`/`epssPercentile`/`pocCount` on findings: **CISA KEV** (known-exploited, 24h cache, reads `dateAdded` for the freshness marker), optional **VulnCheck KEV** community union (`VULNCHECK_API_KEY`, wider/faster), **FIRST EPSS** (batched 100/req), and **nomi-sec PoC-in-GitHub** (public PoC counts, bounded+cached, no key). Best-effort; `FIXLY_DISABLE_INTEL=1` to disable. KEV/EPSS failures warn; the supplementary PoC feed degrades silently. Pure freshness helpers `kevAgeDays`/`isNewlyExploited` live in the client-safe [kev.ts](packages/core/src/kev.ts) (`@fixly/core/kev`). We consume EPSS/PoC data rather than re-modeling it.
   - [verdict.ts](packages/core/src/verdict.ts) `checkPackage(name, version?)` → SAFE/CAUTION/BLOCK + plain-English reasons. Name-only checks evaluate the LATEST version (what an install fetches), never the whole advisory history. BLOCK = evidence (MAL- record, nonexistent name, KEV vuln, hard typosquat profile); CAUTION = suspicion. `MAL-` OSV ids set `malicious: true` in normalize.
   - [grade.ts](packages/core/src/grade.ts) `computeGrade(result)` → A–F Fixly Score, deterministic point arithmetic (malicious = automatic F, KEV +25, public PoC +10, EPSS≥0.1 +5), `topFixes` with copy-paste commands (transitive → `overrides` hint). Grade stays deterministic — KEV freshness is a display-only marker, not a score input. Exports `findingPenalty(v)` for the remediation engine.
   - [remediate.ts](packages/core/src/remediate.ts) — **remediation engine** (pure, no network/fs): `buildRemediationPlan(result)` → one action per vulnerable package@version (malware → `remove`, direct → `upgrade` to the highest fixed version across its findings, transitive → `override` via npm `overrides`), each with a copy-paste command and points recovered, plus a **Grade Forecast** — `after` is literally `computeGrade` on the scan minus the fixed findings, so "D (58) → A (96)" is real arithmetic. Findings with no published fix land in `unfixable` and stay in the forecast. `applyRemediationPlan(pkgJsonText, plan)` rewrites package.json (preserves `^`/`~` style + detected indentation; skips packages not declared rather than inventing entries). Same plan powers `fixly fix`, the web Remediation Plan card, and the extension quick fixes.
   - [name-model.ts](packages/core/src/name-model.ts) `scoreNameRisk(name)` — **optional ML signal**: an ONNX name-risk model (trained in `ml/`, see below) scored via `onnxruntime-node`. Loaded lazily; returns null when the model file or runtime is absent (verdict engine falls back to the rule-based typosquat signal). `buildNameFeatures` MUST mirror `ml/fixly_ml/features.py` exactly — the shared feature order is pinned by `ml/models/name-risk.meta.json` and by paired TS/pytest tests. Surfaced in verdicts only for non-popular, low-download packages (gated so it never cries wolf on established names). `onnxruntime-node` is an **optionalDependency** and is marked `external` in every esbuild bundle (ships platform-specific `.node` binaries).

### ml/ (Python ML lab — trains models, exports ONNX for Node)

- **Not a workspace package** (no pnpm/turbo wiring); a standalone Python project. `python -m fixly_ml.dataset` builds the labeled corpus (real OSV `MAL-*` malicious names + popular npm names), `python -m fixly_ml.train` trains a scaled-MLP pipeline and exports `ml/models/name-risk.{onnx,meta.json}`.
- **Train in Python, run in Node.** Tree-ensemble converters currently hit a skl2onnx/onnx bool-attr bug, so the estimator is an MLP (exports cleanly; captures nonlinear feature interaction). Model committed to the repo so Node inference works from a clean checkout.
- Feature parity is a hard contract: `fixly_ml/features.py` ↔ `packages/core/src/name-model.ts`, pinned by `ml/tests/test_features.py` and `packages/core/tests/name-model.test.ts`.
- **Honest scope:** a name-only model is one weak corroborating signal, not a verdict (documented in [ml/README.md](ml/README.md)). Roadmap: behavioral (tarball install-script) malware classifier, then release-anomaly `IsolationForest`. EPSS is consumed, never re-modeled — it already IS the exploit-prediction ML.
7. [scan.ts](packages/core/src/scan.ts):
   - `scanProjectFiles({ packageJson, packageLock, repo, includeTransitive?, nvd? })` — shared core: parse → OSV → normalize → `sortBySeverity` (critical→unknown) → NVD enrich. **Both apps call this.**
   - `runScan(repoUrl)` — fetches files from GitHub, then delegates to `scanProjectFiles`. Used by the web app.

`ScanResult` (in [types.ts](packages/core/src/types.ts)) carries `dependencies`, `totalPackages` + `directPackages`/`transitivePackages` + `resolvedPackages` (checked), a `target` (owner/repo, branch used, subpath, `filesFound`/`filesMissing`), `source: "osv" | "osv+nvd"`, `warnings: string[]`, and a structured `error?: { code: ScanErrorCode; message }`. `Severity` includes `"unknown"`. Core has no React/DOM/Next imports — it must keep running in both the Next server and the VS Code (Node) extension host.

### apps/web (`@fixly/web`)

- [components/ScanForm.tsx](apps/web/components/ScanForm.tsx) (client) — validates with `parseGitHubUrl` from `@fixly/core/url`, then pushes to `/dashboard/results?repo=<url>`.
- [app/dashboard/results/page.tsx](apps/web/app/dashboard/results/page.tsx) — async **Server Component** calls `runScan(repo)` from `@fixly/core`. [loading.tsx](apps/web/app/dashboard/results/loading.tsx) is the Suspense spinner. Shows summary, score card, **Remediation Plan card** ([components/RemediationPlanCard.tsx](apps/web/components/RemediationPlanCard.tsx), Grade Forecast + ordered actions from `buildRemediationPlan`), delta banner, warnings panel, findings table (client, direct/transitive filter), and raw JSON.
- **Scan history** ([lib/history.ts](apps/web/lib/history.ts)) — localStorage-backed (`fixly.scan-history.v1`, 50-entry cap), exposed as an external store (`subscribeHistory`/`getHistorySnapshot` for `useSyncExternalStore`). [components/ScanHistoryRecorder.tsx](apps/web/components/ScanHistoryRecorder.tsx) records each scan post-paint (idempotent per repo+scannedAt) and renders the new/resolved/unchanged banner; [components/RecentScans.tsx](apps/web/components/RecentScans.tsx) lists history on the dashboard. **By design there is no server-side persistence.**
- [app/dashboard/page.tsx](apps/web/app/dashboard/page.tsx) — the honest scanner home (form + Recent scans + scope note). **No mock data, no fake projects/scans, no dead links** (the old mock dashboard was removed in the workspace refactor).
- [app/api/scan/route.ts](apps/web/app/api/scan/route.ts) — `POST {repoUrl}` → `runScan`; maps structured error codes to HTTP status. Programmatic entry, not used by the UI.
- [app/page.tsx](apps/web/app/page.tsx) — marketing landing.
- Consumes `@fixly/core`/`@fixly/ui` as **source** via `transpilePackages` in [next.config.ts](apps/web/next.config.ts). Tailwind scans the UI package via an `@source` directive in [app/globals.css](apps/web/app/globals.css).

### apps/cli (`fixly-cli`, bin `fixly`)

- [src/cli.ts](apps/cli/src/cli.ts) — `node:util` parseArgs dispatcher (zero runtime deps; esbuild-bundled ESM with shebang → `dist/cli.js`; run built CLI via `node apps/cli/dist/cli.js`).
- **`fixly vibecheck [dir]`** — local scan (full tree) → `computeGrade` → grade box, headline, top fixes, share line. Exit 0/2.
- **`fixly scan [dir|github-url]`** — human report, `--json`, `--sarif` (SARIF 2.1.0, [src/sarif.ts](apps/cli/src/sarif.ts): KEV/malicious escalate to `error`, transitive findings point at package-lock.json), `--fail-on critical|high|medium|low|any|never` (default never; **malware always fails a gate**), `--no-transitive`. Exit 0 ok / 1 gate / 2 error.
- **`fixly check <pkg>[@version]`** — `checkPackage` verdict; exit 0 safe / 1 caution / 2 block (scriptable).
- **`fixly fix [dir]`** ([src/commands/fix.ts](apps/cli/src/commands/fix.ts)) — prints the remediation plan + Grade Forecast (dry run; `--json`); `--write` applies it to package.json via `applyRemediationPlan` and tells the user to `npm install && fixly vibecheck`. Never runs installs itself.
- **`fixly watch [dir]`** ([src/commands/watch.ts](apps/cli/src/commands/watch.ts)) — live mode: `fs.watch` on package.json/package-lock.json (1s debounce, overlap guard), re-scans on change and prints a timestamped grade line with the scan-over-scan delta (`+n new` / `−n resolved` via `compareFindingKeys`) and a "fixable to X — run fixly fix" nudge. Runs until Ctrl+C.
- **`fixly daemon [dir ...]`** ([src/commands/daemon.ts](apps/cli/src/commands/daemon.ts), spec: [docs/daemon.md](docs/daemon.md)) — **the real-time remediation engine**: file events (~1s) + an advisory-clock re-scan (`--interval`, default 10 min, NVD off per cycle) diffed against persisted per-project snapshots ([src/daemon-state.ts](apps/cli/src/daemon-state.ts), `~/.fixly/daemon-state.json`, `FIXLY_HOME` override). On new/KEV-escalated findings it **auto-remediates by default**: `applyRemediationPlan` → `npm install` → re-scan to verify → report measured MTTR; `--notify-only`/`--no-install` dial it back; desktop toasts + `--webhook` JSON events ([src/notify.ts](apps/cli/src/notify.ts), zero deps, best-effort). Baselines never auto-fix; unfixable findings are reported honestly and never re-alert. Event/remediate logic tested via injected IO in [tests/daemon.test.ts](apps/cli/tests/daemon.test.ts).
- **`fixly guard -- <npm|pnpm|yarn|bun> <install|i|add> …`** ([src/commands/guard.ts](apps/cli/src/commands/guard.ts)) — verdict-checks the packages **named on the command line** before running the real install (block aborts exit 2, `--force` overrides; caution prompts, `--yes` for CI; bare lockfile installs pass through with a vibecheck nudge). A pre-install check, NOT a firewall — transitive deps and hand-edited manifests are not pre-checked. Gating flow tested in [tests/guard.test.ts](apps/cli/tests/guard.test.ts).
- [src/local.ts](apps/cli/src/local.ts) shares the core pipeline for on-disk projects; [src/ui.ts](apps/cli/src/ui.ts) is zero-dep ANSI honoring NO_COLOR/non-TTY.

### apps/mcp (`fixly-mcp`)

- MCP server over stdio ([src/index.ts](apps/mcp/src/index.ts)); tools defined in [src/server.ts](apps/mcp/src/server.ts) via `@modelcontextprotocol/sdk` + zod. Tool descriptions are written FOR the model (when to call, what verdicts mean).
- **Compact-response contract** ([src/responses.ts](apps/mcp/src/responses.ts)): tools return verdict-shaped JSON (≤5 reasons, ≤5 fixes, malicious/KEV callouts) — NEVER raw finding dumps; agent context is scarce. Keep this contract when adding tools.
- Local scanning shared via **`@fixly/core/node`** (`scanLocalProject` — node:fs, kept out of the root barrel; CLI re-exports it).
- Tests are protocol-level: a real MCP `Client` over `InMemoryTransport` with fetch mocked ([tests/server.test.ts](apps/mcp/tests/server.test.ts)).
- Install for Claude Code: `claude mcp add fixly -- node <repo>/apps/mcp/dist/index.js` (see [apps/mcp/README.md](apps/mcp/README.md)).

### apps/extension (`fixly-vscode`)

- Commands **Fixly: Scan Current Project** (`fixly.scanCurrentProject`) and **Fixly: Show Last Report** (`fixly.showReport`, also the status-bar click target).
- [src/scanner.ts](apps/extension/src/scanner.ts) reads the workspace `package.json`/`package-lock.json` and calls `scanProjectFiles` from `@fixly/core` (no duplicated scanner logic; honors the `fixly.includeTransitive` setting).
- [src/extension.ts](apps/extension/src/extension.ts) wires commands, the "Fixly" output channel, a **status-bar item** (live severity counts, error/warning background), and **on-save rescans** (`onDidSaveTextDocument` on `package.json`/`package-lock.json`, 1.2s debounce, `fixly.scanOnSave` setting, quiet progress). A `scanning` flag prevents overlapping scans.
- [src/diagnostics.ts](apps/extension/src/diagnostics.ts) — **inline alerts**: one `Diagnostic` per vulnerable **direct** dependency, anchored to its `"name":` key in package.json (position-aware; skips value-position matches), severity-mapped (critical/high→Error, medium→Warning, low→Info), `code` links to the advisory. Transitive findings stay in the panel/status bar (no line to point at).
- [src/quickfix.ts](apps/extension/src/quickfix.ts) — **Quick Fix code actions** on Fixly diagnostics: the lightbulb rewrites the direct dependency's version range in package.json to the remediation engine's target (preserving `^`/`~` style); saving triggers the on-save rescan, closing the fix→verify loop in-editor. Direct upgrades only — transitive/malware actions stay in the panel.
- [src/panel.ts](apps/extension/src/panel.ts) renders a webview report (**Fixly Score card** via `computeGrade` with top fixes, summary cards, findings table with transitive chips + NVD scores, warnings, **Rescan / Copy Summary / Export JSON**); `FixlyPanel.updateIfOpen()` refreshes it after on-save scans without stealing focus.
- Bundled with esbuild ([esbuild.mjs](apps/extension/esbuild.mjs), `vscode` external) → `dist/extension.js`.

## Conventions

- **pnpm + Turborepo.** Internal packages export TS/TSX **source** (no build step); consumers transpile. `.npmrc` sets `node-linker=hoisted` (required for Next/Turbopack to resolve transitive deps like `postcss`/`scheduler`). esbuild/sharp/etc. are allow-listed under `pnpm.onlyBuiltDependencies` in the root [package.json](package.json).
- **TS config:** packages extend [tsconfig.base.json](tsconfig.base.json) (strict, `noUnusedLocals/Parameters`). `@fixly/core` keeps `lib: ES2022` + `@types/node` (uses global `fetch`/`Buffer`) — **don't reintroduce `cache: "no-store"`** on fetch (not in Node's `RequestInit`; Next 15+ is uncached by default anyway).
- **ESLint:** `apps/web` uses `eslint-config-next`; other packages re-export [eslint.config.base.mjs](eslint.config.base.mjs).
- **Severity colors** live once in [packages/ui/src/severity.ts](packages/ui/src/severity.ts); use `<Badge>` from `@fixly/ui`. Web uses hardcoded hex Tailwind literals (`bg-[#0A0A0A]`, `text-[#BFC3C7]`) — match that.
- **Network reliability** ([http.ts](packages/core/src/http.ts)): GitHub/OSV/NVD calls go through `fetchWithRetry` (backoff + jitter, retries 429/5xx/network, not 404/403); OSV detail fetches are capped at 8 via `mapWithConcurrency`; NVD fetches are sequential + time-budgeted (see nvd.ts above); `runScan` caches results in-memory ([cache.ts](packages/core/src/cache.ts), 5-min TTL, `clearScanCache()`, `FIXLY_DISABLE_SCAN_CACHE=1` to disable). CI: [.github/workflows/ci.yml](.github/workflows/ci.yml) runs install --frozen-lockfile, lint, typecheck, test, build on PRs (Node 20).
- **Web tests** (`apps/web`) run in Vitest **node** env — full React DOM rendering under Vitest is currently broken in this toolchain (react/react-dom dual-instance), so scan-page coverage is module-load + URL-gate logic; use Playwright for real page rendering. Core tests are the main suite.

## Scope guardrails (by design — don't "fix" without being asked)

- **npm only** (yarn/pnpm lock files are not parsed), **public repos only**, **unauthenticated GitHub** (rate-limited; optional `GITHUB_TOKEN`).
- Transitive discovery **requires a package-lock.json** — no lock file → direct-only + warning. That's correct behavior, not a bug.
- **NVD never detects** — it only enriches OSV findings that have a CVE, capped by NVD's public rate limits (coverage always stated in a warning). Partial NVD coverage is expected, not a failure.
- A vuln with no CVSS v3 vector and no `database_specific.severity` correctly resolves to `"unknown"`.
- Scan history is **browser localStorage only** — keep it that way. No auth, no Supabase/server persistence, no fake data.
- Keep it tight (student capstone). No marketplace packaging for the extension, no CI/CD gating.
- Auto-fixing is allowed in exactly one place: **`fixly daemon`** (real-time remediation is the capstone requirement). Its contract: never auto-fix a baseline, always verify by re-scan before claiming success, `--notify-only` must stay available. Every other surface stays plan/dry-run first (`fixly fix` requires `--write`; extension quick fixes are user-invoked).
