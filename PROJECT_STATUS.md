# Project status

Read this to understand Fixly in ~90 seconds. (Deeper docs: [README](README.md),
[docs/architecture.md](docs/architecture.md), [docs/development.md](docs/development.md).
Demo: [DEMO.md](DEMO.md). Weeks 5–8 deliverable map: [docs/weeks-5-8.md](docs/weeks-5-8.md).)

## What Fixly is

A scanner for vulnerable **npm dependencies**. It reads a project's
`package.json` / `package-lock.json`, checks every installed package — direct
**and transitive** — against the **OSV** database, cross-references CVEs with
**NVD**, and reports findings. Two surfaces share one scanner (`@fixly/core`):
a Next.js web app (scans a public GitHub repo by URL) and a VS Code extension
(scans the open project, inline in the editor).

## What works now

- Resolve a public GitHub repo from a URL (incl. `tree/<branch>/<subpath>`),
  fetch manifests, and report a precise error for invalid/missing/private/branch cases.
- Parse direct `dependencies` + `devDependencies` **plus the full transitive
  tree** from the lock file (v1/v2/v3) at exact installed versions — nested
  copies at different versions are each checked (NodeGoat: 36 direct → ~1,090
  packages scanned, ~267 findings). Warnings for missing lock files or
  unresolvable ranges.
- Query OSV and normalize findings (severity, CVSS, CVE, fix version, **affected
  ranges**, direct/transitive origin), sorted by severity then package name.
- Cross-reference CVEs against **NVD** for an independent CVSS score
  (best-effort under NVD's public rate limits; `NVD_API_KEY` raises coverage;
  the report states exactly how many CVEs were covered).
- Independently re-verify each finding's installed version against the OSV
  affected range (local semver matcher) and mark limited-confidence cases.
- **Scan history in the browser** (localStorage): "Recent scans" on the
  dashboard and a new/resolved/unchanged **delta banner** on re-scans.
- Reliability: retry with backoff (429/5xx/network), bounded OSV concurrency,
  optional `GITHUB_TOKEN`, in-memory scan cache, low-rate-limit warning.
- Web report (summary, delta banner, warnings, findings table with
  direct/transitive filter, NVD scores) and a VS Code extension with a webview
  report, **inline diagnostics on package.json**, **on-save rescans**
  (`fixly.scanOnSave`), and a live **status-bar** severity indicator.

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

Good demo targets: the bundled **sample fixture** (`/dashboard/results?fixture=vulnerable-demo`,
50+ real OSV findings incl. transitive, no GitHub needed — most reliable),
`https://github.com/OWASP/NodeGoat` (~1,090 packages, ~267 findings — the full-tree showstopper),
`https://github.com/sindresorhus/slugify` (clean). Full click-path in [DEMO.md](DEMO.md).

## Current limitations

- npm only (yarn/pnpm lock files are not parsed → direct-only, approximate).
- Transitive discovery requires `package-lock.json`; without it, direct only (warned).
- Public repos only; unauthenticated GitHub is rate-limited without `GITHUB_TOKEN`.
- No lock file → versions are the range minimum (approximate; warned).
- NVD cross-check is best-effort (public rate limit ≈ 5 req/30s; `NVD_API_KEY`
  raises coverage; coverage is always stated in the report). OSV remains the
  detection source.
- Scan history is per-browser (localStorage) — no accounts, no server database.
- Web page-render tests are pending Playwright (Vitest/React render is broken in
  this toolchain); current web tests cover module load, URL-gate, and history logic.
