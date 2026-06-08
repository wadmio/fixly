# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> Note: a `CLAUDE.md` for an unrelated project ("Opsidian Voice Agent OS") lives in the parent
> directory (`C:\Users\Diomio\Desktop\CLAUDE.md`) and gets auto-loaded up the tree. It does **not**
> apply to Fixly — ignore its Retell/voice-agent rules here.

## What this is

Fixly scans projects for vulnerable **npm dependencies** using the **OSV** database. A student capstone. It is a **pnpm + Turborepo workspace** with two apps and two shared packages:

```
apps/web         @fixly/web      Next.js 16 (App Router) web scanner — scans public GitHub repos
apps/extension   fixly-vscode    VS Code extension — scans the local project, webview report
packages/core    @fixly/core     the scanner: GitHub fetch, parsing, OSV client, normalization
packages/ui      @fixly/ui       shared React UI (Badge + severity helpers)
```

Only **OSV** is wired up (the `source` field is hardcoded `"osv"`); NVD is not implemented. Scope is intentionally tight (see guardrails).

## Commands (run from the repo root)

```bash
pnpm install      # pnpm only — do NOT use npm/yarn (no package-lock.json)
pnpm dev          # turbo: runs the web dev server (http://localhost:3000)
pnpm build        # turbo: next build + esbuild bundle the extension
pnpm lint         # turbo: eslint every package
pnpm typecheck    # turbo: tsc --noEmit every package
pnpm test         # turbo: vitest (tests live in packages/core)
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
2. [parse-packages.ts](packages/core/src/parse-packages.ts) `parseDependencies()` — direct `dependencies` + `devDependencies` only → `DependencyEntry[]` (`requestedVersion`, lock-exact `installedVersion`, `dependencyType`, `sourceFile`) + warnings; lock v1/v2/v3, **top-level only, no transitive**. `resolveCheckVersion()` = lock version ?? range minimum; unresolvable specifiers (`*`, `latest`, npm aliases) are skipped + warned, never invented.
3. [osv.ts](packages/core/src/osv.ts) `queryOsvBatch()` — POST `/querybatch` (ecosystem hardcoded `"npm"`) → GET `/vulns/{id}`. Returns `{ results, warnings }`.
4. [normalize.ts](packages/core/src/normalize.ts) `normalizeOsvResults()` — severity priority: `database_specific.severity` → locally-computed **CVSS v3.1 base score** (`cvssV3BaseScore()`) → per-`affected` → `"unknown"`.
5. [scan.ts](packages/core/src/scan.ts):
   - `scanProjectFiles({ packageJson, packageLock, repo })` — shared core: parse → OSV → normalize → `sortBySeverity` (critical→unknown). **Both apps call this.**
   - `runScan(repoUrl)` — fetches files from GitHub, then delegates to `scanProjectFiles`. Used by the web app.

`ScanResult` (in [types.ts](packages/core/src/types.ts)) carries `dependencies`, `totalPackages` (declared) + `resolvedPackages` (checked), a `target` (owner/repo, branch used, subpath, `filesFound`/`filesMissing`), `warnings: string[]`, and a structured `error?: { code: ScanErrorCode; message }`. `Severity` includes `"unknown"`. Core has no React/DOM/Next imports — it must keep running in both the Next server and the VS Code (Node) extension host.

### apps/web (`@fixly/web`)

- [components/ScanForm.tsx](apps/web/components/ScanForm.tsx) (client) — validates with `parseGitHubUrl` from `@fixly/core/url`, then pushes to `/dashboard/results?repo=<url>`.
- [app/dashboard/results/page.tsx](apps/web/app/dashboard/results/page.tsx) — async **Server Component** calls `runScan(repo)` from `@fixly/core`. [loading.tsx](apps/web/app/dashboard/results/loading.tsx) is the Suspense spinner. Shows summary, a warnings panel, the findings table, and raw JSON.
- [app/dashboard/page.tsx](apps/web/app/dashboard/page.tsx) — the honest scanner home (form + scope note). **No mock data, no fake projects/scans, no dead links** (the old mock dashboard was removed in the workspace refactor).
- [app/api/scan/route.ts](apps/web/app/api/scan/route.ts) — `POST {repoUrl}` → `runScan`; maps structured error codes to HTTP status. Programmatic entry, not used by the UI.
- [app/page.tsx](apps/web/app/page.tsx) — marketing landing.
- Consumes `@fixly/core`/`@fixly/ui` as **source** via `transpilePackages` in [next.config.ts](apps/web/next.config.ts). Tailwind scans the UI package via an `@source` directive in [app/globals.css](apps/web/app/globals.css).

### apps/extension (`fixly-vscode`)

- Command **Fixly: Scan Current Project** (`fixly.scanCurrentProject`).
- [src/scanner.ts](apps/extension/src/scanner.ts) reads the workspace `package.json`/`package-lock.json` and calls `scanProjectFiles` from `@fixly/core` (no duplicated scanner logic).
- [src/panel.ts](apps/extension/src/panel.ts) renders a webview report (summary cards, findings table, warnings, **Rescan / Copy Summary / Export JSON**). [src/extension.ts](apps/extension/src/extension.ts) wires the command + a "Fixly" output channel.
- Bundled with esbuild ([esbuild.mjs](apps/extension/esbuild.mjs), `vscode` external) → `dist/extension.js`.

## Conventions

- **pnpm + Turborepo.** Internal packages export TS/TSX **source** (no build step); consumers transpile. `.npmrc` sets `node-linker=hoisted` (required for Next/Turbopack to resolve transitive deps like `postcss`/`scheduler`). esbuild/sharp/etc. are allow-listed under `pnpm.onlyBuiltDependencies` in the root [package.json](package.json).
- **TS config:** packages extend [tsconfig.base.json](tsconfig.base.json) (strict, `noUnusedLocals/Parameters`). `@fixly/core` keeps `lib: ES2022` + `@types/node` (uses global `fetch`/`Buffer`) — **don't reintroduce `cache: "no-store"`** on fetch (not in Node's `RequestInit`; Next 15+ is uncached by default anyway).
- **ESLint:** `apps/web` uses `eslint-config-next`; other packages re-export [eslint.config.base.mjs](eslint.config.base.mjs).
- **Severity colors** live once in [packages/ui/src/severity.ts](packages/ui/src/severity.ts); use `<Badge>` from `@fixly/ui`. Web uses hardcoded hex Tailwind literals (`bg-[#0A0A0A]`, `text-[#BFC3C7]`) — match that.

## Scope guardrails (by design — don't "fix" without being asked)

- **npm only**, **direct deps only** (no transitive vuln detection), **public repos only**, **unauthenticated GitHub** (rate-limited).
- A vuln with no CVSS v3 vector and no `database_specific.severity` correctly resolves to `"unknown"`.
- Keep it tight (student capstone). No NVD, no auth, no Supabase/persistence, no scan history, no fake data. The extension prototype is deliberately minimal (no background scanning, no settings, no marketplace packaging).
