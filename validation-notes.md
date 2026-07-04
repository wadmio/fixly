# Fixly – Scan Result Validation Notes

**Last updated:** 2026-06-14
**Original author:** Riyadh Al-Hoyidy (Phase 2 OSV/CVE validation)
**Updated for:** the product-grade workspace refactor (Weeks 2–6 acceptance);
re-run 2026-06-14 for the Weeks 5–8 matching/affected-range work.

All results below were produced by the real scanner via `pnpm validate`
([scripts/validate.ts](scripts/validate.ts)), which calls `@fixly/core`'s
`runScan` against the live GitHub and OSV APIs (unauthenticated).

---

## What works (verified)

- **Repository fetch** — public repos resolved by URL, including default-branch
  detection and explicit `tree/<branch>/<subpath>` URLs.
- **Dependency extraction** — `package.json` always; `package-lock.json` when
  present; a missing lock file is a warning, not a failure.
- **Dependency parsing** — direct `dependencies` + `devDependencies`, exact
  versions from lock v1/v2/v3, semver ranges resolved where possible,
  unresolvable specifiers skipped **with a warning** (never invented).
- **OSV matching** — CVE/GHSA IDs, severity, CVSS score, fix version, summary.
- **Severity sorting** — critical → high → medium → low → unknown.
- **Structured errors** — `invalid_url`, `repo_not_found`, `private_repo`,
  `branch_not_found`, `no_package_json`, `no_dependencies`, `rate_limited`.
- **Scan target reporting** — owner/repo, branch used, files found/missing,
  subpath.

## What was removed as fake/mock/demo code (refactor)

- `lib/mock-data.ts` — hardcoded fake projects, scans, and vulnerabilities.
- The mock dashboard at `/dashboard` (fake stat cards, fake projects table,
  fake "recent scans") and its **dead** `View results` links to
  `/dashboard/{projectId}/scan/{scanId}` (routes that never existed).
- `StatusDot` and placeholder sidebar nav (Projects/Vulnerabilities/Settings all
  pointed at `/dashboard`) and the fake `user@example.com / Free plan` footer.
- Misleading landing copy (fabricated "180k+ CVEs / <2s" stats; "npm · yarn ·
  pnpm" — only npm is supported; "paste your package.json" — it takes a repo URL).

No fake scan data remains in any product route.

## Current limitations

- npm only; **direct** dependencies only (no transitive analysis).
- Without a lock file, versions are the resolved minimum of each range, so
  results are approximate (surfaced as a warning).
- Unauthenticated GitHub requests are rate-limited (~60/h). Set `GITHUB_TOKEN`
  (server-side) to raise this; `rate_limited` is reported clearly when hit.
- npm alias specifiers (`"x": "npm:y@2"`), git/url, and dist-tag (`latest`)
  versions cannot be resolved and are skipped with a warning.
- Severity is `unknown` when OSV provides neither a CVSS vector nor a database
  severity.

---

## Validation matrix (live runs, 2026-06-14)

| # | Case | Input | Result |
|---|---|---|---|
| 1 | Vulnerable repo | `OWASP/NodeGoat` | 36 deps, **17 vulns** — C1 H10 M5 L1. Branch `master`; `package.json` + `package-lock.json` found. |
| 2 | Clean / low-finding repo | `sindresorhus/slugify` | 4 deps, **0 vulns**. No lock file → approximate-version warning. |
| 3 | Invalid URL | `not-a-real-url` | `invalid_url` error, no crash. |
| 4 | Non-GitHub URL | `https://gitlab.com/foo/bar` | `invalid_url` error. |
| 5 | Repo not found | `wadmio/this-repo-does-not-exist-zzz` | `repo_not_found` error (message notes it may also be private). |
| 6 | Missing package.json | `github/gitignore` | `no_package_json` error on branch `main`. |
| 7 | Branch + subpath | `vercel/next.js` → `tree/canary/packages/next` | 229 deps, **219 resolved**, **22 vulns (C1 H10 M4 L7)**. Branch `canary`, subpath honored; 10 npm-alias specifiers skipped with a warning. (Was 21/no-critical on 2026-06-07 — OSV added an advisory; the live count tracks OSV.) |
| 8 | Local fixture (no GitHub) | `?fixture=vulnerable-demo` | 6 deps, **50+ vulns** across `lodash 4.17.4`, `minimist 1.2.0`, `axios 0.21.0`, `node-fetch 2.6.0`, `handlebars 4.0.11`, `ejs 2.6.1`. Several critical. **Every finding confirmed in-range** by the local matcher (`versionInRange === true`). Queries OSV only — no GitHub fetch, so it can't be rate-limited mid-demo. |

### CVE/GHSA matching check

NodeGoat's 17 findings (C1/H10/M5/L1) match the pre-refactor Phase 2 numbers in
this file's earlier revision, confirming the scanner's matching behavior was
preserved through the extraction into `@fixly/core`. IDs appear as both `GHSA-…`
and `CVE-…`; fix versions render when OSV provides them.

### Error paths covered by unit tests

`branch_not_found`, `private_repo`, and `rate_limited` are hard to trigger on
demand against live GitHub, so they are covered by mocked-`fetch` unit tests in
[packages/core/tests/github-fetch.test.ts](packages/core/tests/github-fetch.test.ts)
alongside the success path.

---

## How to reproduce

```bash
pnpm validate          # runs scripts/validate.ts against the cases above
pnpm --filter @fixly/core test   # unit tests (no network)
```

## Reliability behavior

- **Retry with backoff** — GitHub and OSV requests retry transient failures
  (network errors, 429/5xx) with exponential backoff + jitter (`fetchWithRetry`).
- **OSV concurrency limit** — per-vulnerability detail lookups run at most 8 at a
  time (`mapWithConcurrency`), so vuln-heavy repos don't fan out hundreds of calls.
- **In-memory scan cache** — repeated scans of the same URL return the previous
  result within a 5-minute TTL (per process; dev/demo only). Disable with
  `FIXLY_DISABLE_SCAN_CACHE=1`.
- **Rate-limit warning** — when GitHub's remaining quota is low and no
  `GITHUB_TOKEN` is set, a warning is added to the report.

## Outputs (raw `pnpm validate`, 2026-06-14)

Run with `FIXLY_DISABLE_SCAN_CACHE=1` to force fresh scans (post-reliability changes):

```text
=== vulnerable repo ===
url:     https://github.com/OWASP/NodeGoat
target:  OWASP/NodeGoat branch=master found=[package.json, package-lock.json] missing=[]
deps:    total=36 resolved=36
vulns:   total=17 (C1 H10 M5 L1 U0)

=== small / low-finding repo ===
url:     https://github.com/sindresorhus/slugify
target:  sindresorhus/slugify branch=main found=[package.json] missing=[package-lock.json]
deps:    total=4 resolved=4
vulns:   total=0 (C0 H0 M0 L0 U0)
warning: No package-lock.json found. ... results may be approximate.

=== invalid URL ===
url:     not-a-real-url
error:   invalid_url — Invalid GitHub URL. Use a public github.com repository URL ...

=== non-GitHub URL ===
url:     https://gitlab.com/foo/bar
error:   invalid_url — Invalid GitHub URL ...

=== repo not found ===
url:     https://github.com/wadmio/this-repo-does-not-exist-zzz
error:   repo_not_found — Repository ... was not found ...

=== missing package.json ===
url:     https://github.com/github/gitignore
error:   no_package_json — No package.json found in github/gitignore on branch "main" ...

=== branch + subpath ===
url:     https://github.com/vercel/next.js/tree/canary/packages/next
target:  vercel/next.js branch=canary found=[package.json] missing=[package-lock.json]
deps:    total=229 resolved=219
vulns:   total=22 (C1 H10 M4 L7 U0)
warning: No package-lock.json found ...
warning: Could not determine a version to check for 10 package(s): ... These were skipped.
```

> Image screenshots of the web report and the VS Code webview can be added here;
> the textual outputs above are the canonical proof and are reproducible via
> `pnpm validate`.


---

## 2026-07-03 — Transitive scanning + NVD cross-referencing + history

Re-validated after adding full lock-tree (transitive) scanning, NVD CVE
enrichment, browser scan history, and the extension's inline diagnostics /
on-save rescan. All checks green: `pnpm lint` / `typecheck` / `test`
(77 core + 8 web) / `build`, plus the live runs below
(`FIXLY_DISABLE_SCAN_CACHE=1 pnpm validate` and a NodeGoat one-off).

```text
=== vulnerable repo (OWASP/NodeGoat, has package-lock.json) ===
packages: 1091 (direct 36 + transitive 1055)   resolved: 1091
vulns:    267 (C27 H141 M81 L17 U1)
  of which transitive: 250 | nvd-checked: 3 | source: osv+nvd
warning:  NVD cross-check covered 5 of 148 CVEs (public NVD API rate limits —
          set NVD_API_KEY to raise coverage). Uncovered findings remain OSV-only.
sample:   babel-traverse@6.11.4 CVE-2023-45133 — OSV CVSS 9.3, NVD CVSS 9.3 (agreement)

=== branch + subpath (vercel/next.js/tree/canary/packages/next, no lock file) ===
deps:    total=229 (direct=229 transitive=0) resolved=219
vulns:   total=25 (C1 H11 M5 L8 U0) source=osv+nvd nvd-checked=5
warning: No package-lock.json found ... Transitive dependencies cannot be
         discovered without a lock file, so only direct dependencies were checked.

All error cases (invalid URL, non-GitHub URL, repo not found, missing
package.json) unchanged — precise structured errors, no crashes.
```

Notes:
- Direct-only NodeGoat used to report ~17 findings; walking the lock tree
  surfaces 267 across 1,091 package@version pairs (nested duplicates included).
- NVD agreement on sampled CVEs (e.g. 9.3 vs 9.3) is the second-source
  verification the proposal called for; coverage is bounded by NVD's public
  rate limit and is always stated in the report warnings.
