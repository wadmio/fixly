# Architecture

Fixly is a pnpm + Turborepo workspace. One shared scanner package is consumed by two front ends.

```
                         ┌─────────────────────────────┐
                         │        @fixly/core          │
                         │  (no React / DOM / Next)    │
                         │                             │
   GitHub repo URL  ─────┤ runScan(repoUrl)            │
                         │   └─ fetchProjectFiles ──┐  │
                         │                          ▼  │
   local files      ─────┤ scanProjectFiles ──► parsePackages ──► queryOsvBatch ──► normalize ──► sortBySeverity
                         │                                                                         │
                         └──────────────────────────────────────────────────────────────────────┘
                                          │                                   │
                                  ScanResult (web)                    ScanResult (extension)
                                          │                                   │
                                ┌─────────▼─────────┐               ┌─────────▼─────────┐
                                │   @fixly/web       │               │   fixly-vscode     │
                                │  Next.js server    │               │  webview report    │
                                │  component + UI    │               │  + output channel  │
                                └────────────────────┘               └────────────────────┘
```

## Packages

| Package | Name | Role |
|---|---|---|
| `packages/core` | `@fixly/core` | All scanning logic. Pure TypeScript; uses global `fetch` and `Buffer`. Must run in both the Next server runtime and the VS Code (Node) extension host, so it has **no** React/DOM/Next dependencies. |
| `packages/ui` | `@fixly/ui` | Small shared React UI — `Badge` and severity label/style helpers. Consumed by the web app today; available to an extension webview later. |
| `apps/web` | `@fixly/web` | Next.js 16 App Router web scanner. |
| `apps/extension` | `fixly-vscode` | VS Code extension prototype. |

## Core data flow

1. **Acquire manifests.**
   - Web: `runScan(repoUrl)` → `parseGitHubUrl` → `fetchProjectFiles` downloads `package.json` /
     `package-lock.json` (GitHub Contents API, with a raw.githubusercontent.com fallback across
     candidate branches). Unauthenticated, so subject to GitHub rate limits; 401/403 → "private".
   - Extension: reads the same two files from the open workspace folder.
2. **Resolve dependencies.** `parsePackages` takes the direct `dependencies` + `devDependencies`
   and resolves each to a concrete version, preferring the lock file (v1 `dependencies`, v2/v3
   top-level `packages`). It returns `{ packages, warnings }` — warnings cover a missing lock file
   and unresolvable version ranges (`*`, dist-tags, …), which are skipped.
3. **Query OSV.** `queryOsvBatch` POSTs to `/querybatch` (ecosystem hardcoded `npm`) to find which
   packages are vulnerable, then fetches full records from `/vulns/{id}`. Returns `{ results,
   warnings }`; warnings note any detail lookups that failed.
4. **Normalize.** `normalizeOsvResults` maps each OSV record to a `ScanVulnerability`. Severity is
   resolved in priority order: top-level `database_specific.severity` → a locally computed CVSS v3.1
   base score (`cvssV3BaseScore`) → per-`affected` severity fields → `unknown`. It also extracts the
   fix version and the `CVE-` alias.
5. **Assemble.** `scanProjectFiles` sorts findings by severity (critical → unknown) and returns a
   `ScanResult` carrying `totalPackages`, `vulnerabilities`, and the accumulated `warnings`
   (plus an `error` string when the scan could not complete).

`runScan` (remote) and `scanProjectFiles` (already-loaded files) share steps 2–5 — the extension and
web app produce identical reports for the same inputs.

## Key decisions

- **One scanner, two front ends.** The extension calls `scanProjectFiles` directly; nothing is
  reimplemented. The web app's `runScan` is just `fetchProjectFiles` + `scanProjectFiles`.
- **Source-only internal packages.** `@fixly/core` and `@fixly/ui` export `.ts`/`.tsx` source (no
  build step). The web app compiles them via `transpilePackages`; the extension bundles them with
  esbuild. This keeps the dev loop simple and avoids stale `dist/`.
- **`node-linker=hoisted`.** Next.js/Turbopack needs some transitive deps (`postcss`, `scheduler`)
  resolvable from `apps/web`. A hoisted node_modules layout (`.npmrc`) keeps that working on pnpm.
- **OSV only.** `ScanResult.source` is hardcoded `"osv"`. NVD is intentionally not implemented.
