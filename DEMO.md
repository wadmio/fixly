# Fixly — Demo Guide

A professor-facing walkthrough: set up, run, scan a project, and read the
findings. Fixly extracts a project's dependency files, parses installed
versions, checks them against the **OSV** vulnerability database, and shows the
results.

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

This scans a **bundled** project of real, known-vulnerable packages. It does
**not** call GitHub, so it cannot be rate-limited during a live demo. It returns
50+ real OSV findings (several critical), each confirmed in-range by Fixly's
matcher.

(You can also reach it by opening `http://localhost:3000/dashboard` and clicking
**“Try a sample scan.”**)

## 4. Backup demo URL / fixture

If you want to show a **real public GitHub repository** (proves the full
extraction flow), paste one into the dashboard form:

| Repo | Shows |
|---|---|
| `https://github.com/OWASP/NodeGoat` | A deliberately vulnerable app — **~17 findings** (1 critical). |
| `https://github.com/sindresorhus/slugify` | A clean library — **0 findings** + a "no lockfile, approximate" warning. |

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

### B) Terminal verification testing

Run each command from the repo root:

| Command | What it proves | Expected success result |
|---|---|---|
| `pnpm validate` | The real scanner works end-to-end against live GitHub + OSV (vulnerable repo, clean repo, and every error case). | Prints reports: `OWASP/NodeGoat` ≈ 17 vulns, `slugify` 0 vulns, and clean `invalid_url` / `repo_not_found` / `no_package_json` errors. |
| `pnpm test` | Parsing, OSV normalization, and version matching logic are correct (unit tests, no network). | `60 passed` in `packages/core` + `3 passed` in `apps/web`. |
| `pnpm lint` | Code style/quality rules pass across every package. | `Tasks: 4 successful`. |
| `pnpm typecheck` | TypeScript types are sound across every package. | `Tasks: 4 successful`. |
| `pnpm build` | The web app and VS Code extension both compile for production. | `Compiled successfully` (web) + extension `dist/extension.js` built. |

---

## 6. What to say while presenting

- “Fixly scans the **GitHub repository** behind a Node.js app — not a live
  website. It reads `package.json` and `package-lock.json`.”
- “I’ll use a **bundled vulnerable fixture** so the demo doesn’t depend on
  GitHub’s rate limit. These are real packages at old versions.”
- Point at a row: “This is the **installed version**, the **affected range** OSV
  matched it against, the **CVE**, the **severity/CVSS**, and the **fixed
  version** to upgrade to.”
- “Findings are sorted by **severity, then package name**.”
- “If there’s no lockfile, I check the **minimum** of the declared range and
  label it **approximate** — I never invent a version.”
- “Then I’ll scan a **real repo, OWASP/NodeGoat**, to show the full extraction
  flow from a live URL.”

---

## 7. Known limitations (state these honestly)

- **npm only** — no yarn/pnpm/other ecosystems.
- **Direct dependencies only** — transitive/nested dependencies are not scanned.
- **OSV is implemented; NVD is future work** — NVD is documented but not wired up.
- **Missing lockfiles create approximate results** — without `package-lock.json`,
  Fixly checks the minimum of each declared range and tags those findings `(≈ approx)`.
- **Severity / CVSS are only shown when OSV provides them** — otherwise the badge
  reads `unknown`; nothing is fabricated.
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
