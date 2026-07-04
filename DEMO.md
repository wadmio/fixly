# Fixly — Demo Guide

A professor-facing walkthrough: set up, run, scan a project, and read the
findings. Fixly extracts a project's dependency files, parses installed
versions (direct **and transitive**, from the lock file tree), checks them
against the **OSV** vulnerability database, cross-references CVEs against
**NVD**, and shows the results — with scan-over-scan history in the browser.
Beyond the web app and VS Code extension, the same core powers a **CLI**
(`fixly vibecheck` / `scan` / `check` / `guard`) and an **MCP server** for AI
coding agents — see section A3 below.

---

## 1. Setup (once)

```bash
pnpm install        # pnpm only — there is no package-lock.json / npm support
```

- Node.js 20 (`.nvmrc`). **No API keys required.**
- A `GITHUB_TOKEN` is optional — it only raises GitHub's rate limit and is **not**
  needed for the demo. See [docs/development.md](docs/development.md).

## 2. Start command

```bash
pnpm dev            # starts the web app at http://localhost:3000
```

## 3. Main demo URL (recommended)

```
http://localhost:3000/dashboard/results?fixture=vulnerable-demo
```

This scans a **bundled** project of real, known-vulnerable packages — including
two that exist only in the lock file (transitive). It does **not** call GitHub,
so it cannot be rate-limited during a live demo. It returns 50+ real OSV
findings (several critical), each confirmed in-range by Fixly's matcher, with
the worst CVEs cross-checked against NVD. Scanning it twice also demonstrates
the **"since the last scan"** delta banner and the dashboard's **Recent scans**
history.

(You can also reach it by opening `http://localhost:3000/dashboard` and clicking
**“Try a sample scan.”**)

## 4. Backup demo URL / fixture

If you want to show a **real public GitHub repository** (proves the full
extraction flow), paste one into the dashboard form:

| Repo | Shows |
|---|---|
| `https://github.com/OWASP/NodeGoat` | A deliberately vulnerable app — **~1,090 packages scanned (36 direct + ~1,055 transitive), ~267 findings (~27 critical)**. The headline demo of full-tree scanning. |
| `https://github.com/sindresorhus/slugify` | A clean library — **0 findings** + a "no lockfile, approximate, direct-only" warning. |

The bundled fixture above is the **safest** path; use these if GitHub is responsive.

---

## 5. How to test the demo

> **Professor-facing summary:** To test Fixly, I first run automated checks from
> the terminal to verify parsing, API normalization, and matching logic. Then I
> test the browser demo using the bundled vulnerable fixture so the demo does not
> depend on GitHub rate limits. Finally, I test a real public GitHub repository
> to prove the extraction flow works end-to-end.

### A) Browser demo testing

1. Start the app: `pnpm dev`.
2. Open `http://localhost:3000/dashboard/results?fixture=vulnerable-demo`.
3. Confirm the page **loads without crashing** (HTTP 200).
4. Confirm the page shows:
   - the scanned source / fixture name (“Sample: intentionally-vulnerable Node project”),
   - dependency files found (`package.json`, `package-lock.json`),
   - parsed dependency count (declared vs. checked),
   - vulnerabilities found (the “N vulnerabilities found” heading + severity cards),
   - a findings table,
   - CVE aliases where available,
   - severity / CVSS where available,
   - fixed version where available,
   - the affected range each finding matched (`affects <…`),
   - warnings / limitations (when present).
5. Click around the dashboard — confirm **no broken routes** (`/`, `/dashboard`,
   the results page all load).
6. Test at least one **public GitHub repo URL** in the form (e.g. `OWASP/NodeGoat`).
7. Test **bad input** — paste `not-a-real-url`. Confirm a clean error message
   (“Invalid GitHub URL…”) appears instead of a crash.
8. **Re-scan the fixture** (revisit the URL) — confirm the “since the last scan”
   panel appears, and `/dashboard` now shows the scan under **Recent scans**.

### A2) VS Code extension testing

1. `pnpm --filter fixly-vscode build`, then open `apps/extension` in VS Code and press **F5**.
2. In the Extension Development Host, open a Node project (or this repo) and run
   **Fixly: Scan Current Project**.
3. Confirm: the report panel opens, the **status bar** shows severity counts
   (e.g. `Fixly: 3C 5H`), and `package.json` shows **squiggles** on vulnerable
   direct dependencies (hover for CVE + fix version; Problems panel lists them).
4. Edit `package.json` (e.g. downgrade a package), **save**, and wait ~1s —
   confirm Fixly **rescans automatically** and the status bar/diagnostics update.
   (Toggle via the `fixly.scanOnSave` setting.)

### A3) CLI, guard, and MCP testing

Build once (`pnpm build`), then from the repo root (demo targets live in
[examples/](examples/README.md) — manifest-only, nothing installed):

1. **Vibecheck (A–F grade):** `node apps/cli/dist/cli.js vibecheck examples/demo-app` —
   grade **F**, the ⚡ **exploited in the wild (CISA KEV)** badge
   (`mongo-express@0.53.0`, CVE-2019-10758), and the top fixes ranked by points
   recovered. Then `... vibecheck examples/clean-app` — grade **A**, "Ship it."
2. **Verdict check:** `node apps/cli/dist/cli.js check lodahs` — a real malicious
   typosquat of `lodash`; expect **BLOCK** (OSV MAL-2025-25502, exit 2).
   `check express` comes back SAFE (exit 0), and a made-up name is BLOCKED as a
   likely AI hallucination.
3. **Guard:** `node apps/cli/dist/cli.js guard -- npm install lodahs` — the
   install is **blocked before npm runs**, with "did you mean: lodash". A safe
   package passes through to the real package manager.
4. **SARIF/CI gate:** `node apps/cli/dist/cli.js scan examples/demo-app --sarif > fixly.sarif`
   and `... scan examples/demo-app --fail-on high` (exit 1 when a high+ finding exists).
5. **MCP server:** `claude mcp add fixly -- node <repo>/apps/mcp/dist/index.js`,
   then ask the agent to check a package — see [apps/mcp/README.md](apps/mcp/README.md).

### B) Terminal verification testing

Run each command from the repo root:

| Command | What it proves | Expected success result |
|---|---|---|
| `pnpm validate` | The real scanner works end-to-end against live GitHub + OSV + NVD (vulnerable repo, clean repo, and every error case). | Prints reports: `OWASP/NodeGoat` ≈ 267 vulns across ~1,090 packages (36 direct + ~1,055 transitive), `slugify` 0 vulns, and clean `invalid_url` / `repo_not_found` / `no_package_json` errors. |
| `pnpm test` | Parsing, OSV normalization, version matching, NVD enrichment, verdicts/grade, history-diff, CLI, and MCP protocol logic are correct (unit tests, no network). | All suites pass: `packages/core` (100+), `apps/web`, `apps/cli`, `apps/mcp`. |
| `pnpm lint` | Code style/quality rules pass across every package. | All tasks successful. |
| `pnpm typecheck` | TypeScript types are sound across every package. | All tasks successful. |
| `pnpm build` | The web app, CLI, MCP server, and VS Code extension all compile for production. | `Compiled successfully` (web) + `dist/` bundles for cli/mcp/extension. |

---

## 6. What to say while presenting

- “Fixly scans the **GitHub repository** behind a Node.js app — not a live
  website. It reads `package.json` and `package-lock.json`.”
- “I’ll use a **bundled vulnerable fixture** so the demo doesn’t depend on
  GitHub’s rate limit. These are real packages at old versions.”
- Point at a row: “This is the **installed version**, the **affected range** OSV
  matched it against, the **CVE**, the **severity/CVSS**, and the **fixed
  version** to upgrade to.”
- Point at a `transitive` chip: “This package isn’t in `package.json` at all —
  another dependency pulled it in. Fixly walks the **entire lock file tree**,
  so nested copies at different versions are each checked.”
- Point at `NVD 9.8` under a severity: “OSV found it; **NVD independently
  scores the same CVE** — two databases agreeing is much stronger evidence.
  When NVD rate-limits us, the report says exactly how many CVEs were covered.”
- “Findings are sorted by **severity, then package name** — and the toggle
  filters **direct vs transitive**.”
- “If there’s no lockfile, I check the **minimum** of the declared range and
  label it **approximate** — I never invent a version. Transitive discovery
  needs the lock file, and the report says so.”
- Rescan the fixture: “Fixly remembers previous scans **in the browser** — this
  banner shows **new / resolved / unchanged** findings since last time, and the
  dashboard lists recent scans with severity totals.”
- “Then I’ll scan a **real repo, OWASP/NodeGoat**: ~36 direct dependencies, but
  Fixly checks **~1,090 packages** once the lock tree is included — ~267 real
  findings.”

---

## 7. Known limitations (state these honestly)

- **npm only** — no yarn/pnpm/other ecosystems (yarn.lock / pnpm-lock.yaml are
  not parsed; those repos scan as "no lockfile → direct only, approximate").
- **Transitive discovery requires `package-lock.json`** — without it, only
  direct dependencies can be checked (and the report says so).
- **NVD cross-referencing is best-effort** — the public NVD API allows ~5
  requests/30s without a key, so only the worst CVEs get a second opinion per
  scan (an `NVD_API_KEY` env var raises coverage; the report states exactly how
  many CVEs were covered). OSV remains the detection source — NVD never hides
  a finding.
- **Scan history lives in the browser** (localStorage) — by design there are no
  accounts and no server-side storage; history is per-device.
- **Missing lockfiles create approximate results** — without `package-lock.json`,
  Fixly checks the minimum of each declared range and tags those findings `(≈ approx)`.
- **Severity / CVSS are only shown when OSV/NVD provide them** — otherwise the
  badge reads `unknown`; nothing is fabricated.
- **Public GitHub repos can hit rate limits** (~60 req/hr unauthenticated), so the
  **bundled fixture is the safest demo path**.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `rate_limited` error on a GitHub scan | Use the **fixture** (`?fixture=vulnerable-demo`), or set `GITHUB_TOKEN` and retry. |
| Repo scan slow / empty | Confirm it's a **public Node.js** repo with a `package.json`. Monorepo? point at a subfolder: `.../tree/<branch>/packages/<name>`. |
| Findings differ from last time | Expected — OSV is live and updates its advisories. |
| Port 3000 in use | `pnpm --filter @fixly/web dev -- -p 3001`. |
| Force fresh scans (skip 5-min cache) | `FIXLY_DISABLE_SCAN_CACHE=1 pnpm dev`. |
