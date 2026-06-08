# Project status

Read this to understand Fixly in ~90 seconds. (Deeper docs: [README](README.md),
[docs/architecture.md](docs/architecture.md), [docs/development.md](docs/development.md).)

## What Fixly is

A scanner for vulnerable **npm dependencies**. It reads a project's
`package.json` / `package-lock.json`, checks each direct dependency against the
**OSV** database, and reports findings. Two surfaces share one scanner
(`@fixly/core`): a Next.js web app (scans a public GitHub repo by URL) and a
VS Code extension (scans the open project).

## What works now

- Resolve a public GitHub repo from a URL (incl. `tree/<branch>/<subpath>`),
  fetch manifests, and report a precise error for invalid/missing/private/branch cases.
- Parse direct `dependencies` + `devDependencies`; exact versions from the lock
  file (v1/v2/v3), with warnings for missing lock files or unresolvable ranges.
- Query OSV and normalize findings (severity, CVSS, CVE, fix version), sorted
  critical → unknown.
- Reliability: retry with backoff (429/5xx/network), bounded OSV concurrency,
  optional `GITHUB_TOKEN`, in-memory scan cache, low-rate-limit warning.
- Web report (summary, warnings, findings table) and a VS Code webview report
  (cards, table, Rescan / Copy Summary / Export JSON).

## Key milestones done

- pnpm + Turborepo workspace (`apps/web`, `apps/extension`, `packages/core`, `packages/ui`).
- Removed the old mock dashboard (no fake data / dead links).
- Structured errors + scan target metadata + reliability layer.
- Tests (Vitest, in `packages/core` + web smoke) and CI on every PR.
- Live validation captured in [validation-notes.md](validation-notes.md).

## Demo path

```bash
pnpm install
pnpm dev          # web at http://localhost:3000 → Open dashboard → paste a public repo URL
pnpm validate     # headless: runs real scans against sample repos (vulnerable, clean, error cases)
pnpm --filter fixly-vscode build   # extension: then press F5 in apps/extension
```

Good demo repos: `https://github.com/OWASP/NodeGoat` (17 findings),
`https://github.com/sindresorhus/slugify` (clean).

## Current limitations

- npm only; **direct** dependencies only (no transitive analysis).
- Public repos only; unauthenticated GitHub is rate-limited without `GITHUB_TOKEN`.
- No lock file → versions are the range minimum (approximate; warned).
- OSV only (NVD planned, not implemented). No auth, no database, no scan history.
- Web page-render tests are pending Playwright (Vitest/React render is broken in
  this toolchain); current web tests cover module load + URL-gate logic.
