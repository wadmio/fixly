# Architecture

Fixly is a pnpm + Turborepo workspace. One shared scanner package is consumed by four front ends
(web app, CLI, MCP server, VS Code extension). The diagram below shows the original two-surface
scan flow; the CLI and MCP server consume the same `scanProjectFiles` pipeline plus the verdict
engine (`checkPackage`) and grade (`computeGrade`).

```
                         ┌─────────────────────────────┐
                         │        @fixly/core          │
                         │  (no React / DOM / Next)    │
                         │                             │
   GitHub repo URL  ─────┤ runScan(repoUrl)            │
                         │   └─ fetchProject ───────┐  │
                         │                          ▼  │
   local files      ─────┤ scanProjectFiles ──► parseDependencies ──► queryOsvBatch ──► normalize ──► sortBySeverity
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
| `apps/cli` | `fixly-cli` | CLI (bin `fixly`): vibecheck, scan (SARIF/CI gate), check, guard. |
| `apps/mcp` | `fixly-mcp` | MCP server (stdio) exposing verdicts/scans to AI coding agents. |
| `apps/extension` | `fixly-vscode` | VS Code extension prototype. |

## Core data flow

1. **Acquire manifests.**
   - Web: `runScan(repoUrl)` → `parseGitHubUrl` → `fetchProject`. `fetchProject` verifies the repo
     and (if given) the branch up front via the GitHub REST API, then downloads `package.json` and
     `package-lock.json`. It returns a discriminated `FetchResult`: on failure a precise code
     (`repo_not_found`, `private_repo`, `branch_not_found`, `no_package_json`, `rate_limited`,
     `github_error`); on success the files plus the resolved branch and `filesFound`/`filesMissing`.
     Requests use an optional, server-side-only `GITHUB_TOKEN`.
   - Extension: reads the same two files from the open workspace folder and records found/missing.
2. **Resolve dependencies.** `parseDependencies` takes the direct `dependencies` + `devDependencies`
   and returns normalized `DependencyEntry` objects — `name`, `requestedVersion` (the range),
   `installedVersion` (exact from the lock file, or `null`), `dependencyType`, `sourceFile` — plus
   warnings (missing lock file, unresolvable ranges). `resolveCheckVersion(entry)` picks the version
   to check against OSV: the lock version, else the resolved minimum of the range; unresolvable
   specifiers (`*`, `latest`, npm aliases, git/url) are skipped and warned, never invented.
3. **Query OSV.** `queryOsvBatch` POSTs to `/querybatch` (ecosystem hardcoded `npm`) to find which
   packages are vulnerable, then fetches full records from `/vulns/{id}`. Returns `{ results,
   warnings }`; warnings note any detail lookups that failed.
4. **Normalize.** `normalizeOsvResults` maps each OSV record to a `ScanVulnerability`. Severity is
   resolved in priority order: top-level `database_specific.severity` → a locally computed CVSS v3.1
   base score (`cvssV3BaseScore`) → per-`affected` severity fields → `unknown`. It also extracts the
   fix version and the `CVE-` alias.
5. **Enrich.** `enrichWithNvd` cross-references findings that carry a CVE against NVD for an
   independent CVSS opinion (best-effort, rate-limit aware, never fails a scan; `ScanResult.source`
   becomes `"osv+nvd"`), and `enrichWithIntel` stamps CISA KEV / EPSS exploit intelligence.
6. **Assemble.** `scanProjectFiles` sorts findings by severity (critical → unknown) and returns a
   `ScanResult` carrying `dependencies`, `totalPackages` (declared) and `resolvedPackages`
   (checked), `vulnerabilities`, a `target` (owner/repo, branch used, subpath, files found/missing),
   accumulated `warnings`, and a structured `error` (`{ code, message }`) when the scan could not
   complete. The web `/api/scan` route maps each error code to an HTTP status.

`runScan` (remote) and `scanProjectFiles` (already-loaded files) share steps 2–6 — the extension and
web app produce identical reports for the same inputs.

## Key decisions

- **One scanner, two front ends.** The extension calls `scanProjectFiles` directly; nothing is
  reimplemented. The web app's `runScan` is just `fetchProjectFiles` + `scanProjectFiles`.
- **Source-only internal packages.** `@fixly/core` and `@fixly/ui` export `.ts`/`.tsx` source (no
  build step). The web app compiles them via `transpilePackages`; the extension bundles them with
  esbuild. This keeps the dev loop simple and avoids stale `dist/`.
- **`node-linker=hoisted`.** Next.js/Turbopack needs some transitive deps (`postcss`, `scheduler`)
  resolvable from `apps/web`. A hoisted node_modules layout (`.npmrc`) keeps that working on pnpm.
- **OSV detects, NVD enriches.** OSV is the only detection source. NVD is consulted best-effort,
  per CVE, purely to add an independent CVSS opinion (`ScanResult.source` is `"osv"` or
  `"osv+nvd"`); partial NVD coverage is expected and stated in a warning, never a failure.

## Reliability

- **Retry + backoff** ([http.ts](../packages/core/src/http.ts) `fetchWithRetry`) — GitHub and OSV
  requests retry transient failures (network errors, 429/5xx) with exponential backoff + jitter,
  honoring `Retry-After`. Definitive responses (404/403) are not retried.
- **Bounded OSV concurrency** (`mapWithConcurrency`) — at most 8 vulnerability-detail requests run
  at once.
- **In-memory scan cache** ([cache.ts](../packages/core/src/cache.ts)) — `runScan` returns a cached
  result for the same URL within a 5-minute TTL (per process; dev/demo). Disable with
  `FIXLY_DISABLE_SCAN_CACHE=1`; clear via `clearScanCache()`.
- **Rate-limit warning** — `fetchProject` adds a warning when GitHub's remaining quota is low and no
  `GITHUB_TOKEN` is set.
