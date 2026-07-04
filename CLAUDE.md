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
packages/core    @fixly/core     the scanner: GitHub fetch, parsing, OSV client, NVD enrichment, normalization
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
   - [intel.ts](packages/core/src/intel.ts) — CISA KEV (known-exploited, 24h cache) + FIRST EPSS (exploit probability, batched 100/req) enrichment; stamps `knownExploited`/`epssScore`/`epssPercentile` on findings. Best-effort; `FIXLY_DISABLE_INTEL=1` to disable. We consume EPSS rather than re-modeling it.
   - [verdict.ts](packages/core/src/verdict.ts) `checkPackage(name, version?)` → SAFE/CAUTION/BLOCK + plain-English reasons. Name-only checks evaluate the LATEST version (what an install fetches), never the whole advisory history. BLOCK = evidence (MAL- record, nonexistent name, KEV vuln, hard typosquat profile); CAUTION = suspicion. `MAL-` OSV ids set `malicious: true` in normalize.
   - [grade.ts](packages/core/src/grade.ts) `computeGrade(result)` → A–F Fixly Score, deterministic point arithmetic (malicious = automatic F, KEV +25, EPSS≥0.1 +5), `topFixes` with copy-paste commands (transitive → `overrides` hint).
7. [scan.ts](packages/core/src/scan.ts):
   - `scanProjectFiles({ packageJson, packageLock, repo, includeTransitive?, nvd? })` — shared core: parse → OSV → normalize → `sortBySeverity` (critical→unknown) → NVD enrich. **Both apps call this.**
   - `runScan(repoUrl)` — fetches files from GitHub, then delegates to `scanProjectFiles`. Used by the web app.

`ScanResult` (in [types.ts](packages/core/src/types.ts)) carries `dependencies`, `totalPackages` + `directPackages`/`transitivePackages` + `resolvedPackages` (checked), a `target` (owner/repo, branch used, subpath, `filesFound`/`filesMissing`), `source: "osv" | "osv+nvd"`, `warnings: string[]`, and a structured `error?: { code: ScanErrorCode; message }`. `Severity` includes `"unknown"`. Core has no React/DOM/Next imports — it must keep running in both the Next server and the VS Code (Node) extension host.

### apps/web (`@fixly/web`)

- [components/ScanForm.tsx](apps/web/components/ScanForm.tsx) (client) — validates with `parseGitHubUrl` from `@fixly/core/url`, then pushes to `/dashboard/results?repo=<url>`.
- [app/dashboard/results/page.tsx](apps/web/app/dashboard/results/page.tsx) — async **Server Component** calls `runScan(repo)` from `@fixly/core`. [loading.tsx](apps/web/app/dashboard/results/loading.tsx) is the Suspense spinner. Shows summary, delta banner, warnings panel, findings table (client, direct/transitive filter), and raw JSON.
- **Scan history** ([lib/history.ts](apps/web/lib/history.ts)) — localStorage-backed (`fixly.scan-history.v1`, 50-entry cap), exposed as an external store (`subscribeHistory`/`getHistorySnapshot` for `useSyncExternalStore`). [components/ScanHistoryRecorder.tsx](apps/web/components/ScanHistoryRecorder.tsx) records each scan post-paint (idempotent per repo+scannedAt) and renders the new/resolved/unchanged banner; [components/RecentScans.tsx](apps/web/components/RecentScans.tsx) lists history on the dashboard. **By design there is no server-side persistence.**
- [app/dashboard/page.tsx](apps/web/app/dashboard/page.tsx) — the honest scanner home (form + Recent scans + scope note). **No mock data, no fake projects/scans, no dead links** (the old mock dashboard was removed in the workspace refactor).
- [app/api/scan/route.ts](apps/web/app/api/scan/route.ts) — `POST {repoUrl}` → `runScan`; maps structured error codes to HTTP status. Programmatic entry, not used by the UI.
- [app/page.tsx](apps/web/app/page.tsx) — marketing landing.
- Consumes `@fixly/core`/`@fixly/ui` as **source** via `transpilePackages` in [next.config.ts](apps/web/next.config.ts). Tailwind scans the UI package via an `@source` directive in [app/globals.css](apps/web/app/globals.css).

### apps/extension (`fixly-vscode`)

- Commands **Fixly: Scan Current Project** (`fixly.scanCurrentProject`) and **Fixly: Show Last Report** (`fixly.showReport`, also the status-bar click target).
- [src/scanner.ts](apps/extension/src/scanner.ts) reads the workspace `package.json`/`package-lock.json` and calls `scanProjectFiles` from `@fixly/core` (no duplicated scanner logic; honors the `fixly.includeTransitive` setting).
- [src/extension.ts](apps/extension/src/extension.ts) wires commands, the "Fixly" output channel, a **status-bar item** (live severity counts, error/warning background), and **on-save rescans** (`onDidSaveTextDocument` on `package.json`/`package-lock.json`, 1.2s debounce, `fixly.scanOnSave` setting, quiet progress). A `scanning` flag prevents overlapping scans.
- [src/diagnostics.ts](apps/extension/src/diagnostics.ts) — **inline alerts**: one `Diagnostic` per vulnerable **direct** dependency, anchored to its `"name":` key in package.json (position-aware; skips value-position matches), severity-mapped (critical/high→Error, medium→Warning, low→Info), `code` links to the advisory. Transitive findings stay in the panel/status bar (no line to point at).
- [src/panel.ts](apps/extension/src/panel.ts) renders a webview report (summary cards, findings table with transitive chips + NVD scores, warnings, **Rescan / Copy Summary / Export JSON**); `FixlyPanel.updateIfOpen()` refreshes it after on-save scans without stealing focus.
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
- Keep it tight (student capstone). No marketplace packaging for the extension, no CI/CD gating, no auto-fixing.
