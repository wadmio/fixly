# Fixly – Scan Result Validation Notes

**Last updated:** 2026-06-07
**Original author:** Riyadh Al-Hoyidy (Phase 2 OSV/CVE validation)
**Updated for:** the product-grade workspace refactor (Weeks 2–6 acceptance)

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

## Validation matrix (live runs, 2026-06-07)

| # | Case | Input | Result |
|---|---|---|---|
| 1 | Vulnerable repo | `OWASP/NodeGoat` | 36 deps, **17 vulns** — C1 H10 M5 L1. Branch `master`; `package.json` + `package-lock.json` found. |
| 2 | Clean / low-finding repo | `sindresorhus/slugify` | 4 deps, **0 vulns**. No lock file → approximate-version warning. |
| 3 | Invalid URL | `not-a-real-url` | `invalid_url` error, no crash. |
| 4 | Non-GitHub URL | `https://gitlab.com/foo/bar` | `invalid_url` error. |
| 5 | Repo not found | `wadmio/this-repo-does-not-exist-zzz` | `repo_not_found` error (message notes it may also be private). |
| 6 | Missing package.json | `github/gitignore` | `no_package_json` error on branch `main`. |
| 7 | Branch + subpath | `vercel/next.js` → `tree/canary/packages/next` | 229 deps, **219 resolved**, 21 vulns (H10 M4 L7). Branch `canary`, subpath honored; 10 npm-alias specifiers skipped with a warning. |

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
