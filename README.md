# Fixly

## Dependency security for modern JavaScript projects

Fixly finds vulnerable and malicious third-party **npm** dependencies. It does **not** scan live
websites — it scans a project's dependency manifests (`package.json` / `package-lock.json`), checks
every installed package (direct **and transitive**) against the [OSV](https://osv.dev) vulnerability
database, cross-references CVEs against [NVD](https://nvd.nist.gov) for an independent severity
opinion, and layers on exploit intelligence ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
+ optional [VulnCheck KEV](https://vulncheck.com), [FIRST EPSS](https://www.first.org/epss/), and public
proof-of-concept counts from [nomi-sec PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)) plus a package-verdict engine that catches malicious,
typosquatted, and hallucinated package names **before** they get installed.

Fixly ships **five surfaces over one shared core** (`@fixly/core`):

- **Web scanner** — paste a public GitHub repo URL, get a vulnerability report with an A–F **Fixly Score**.
- **CLI** (`fixly`) — `vibecheck` (10-second grade + top fixes), `scan` (JSON / SARIF / CI gate),
  `check` (SAFE/CAUTION/BLOCK verdict for one package), and `guard` (pre-install check wrapped
  around `npm|pnpm|yarn|bun install`).
- **VS Code extension** — scan the open project in-editor: inline diagnostics on `package.json`,
  on-save (and opt-in as-you-type) rescans, a status-bar indicator, and a webview report with a
  one-click **Apply Remediation Plan** (diff preview + Grade Forecast).
- **MCP server** (`fixly-mcp`) — gives AI coding agents (Claude Code, Cursor, …) security verdicts:
  `check_package`, `scan_project`, `suggest_safe_alternative`.
- **ML lab** (`ml/`) — trains a package-**name**-risk model in Python (on real OSV malware data) and
  exports it to ONNX; the verdict engine runs it in Node as one extra corroborating signal.

> **Demoing or grading this?** See [DEMO.md](DEMO.md) for the click-path,
> [PROJECT_STATUS.md](PROJECT_STATUS.md) for the 90-second overview, and
> [PRESENTATION_NOTES.md](PRESENTATION_NOTES.md) for the speaking script.

---

## Product scope

**In scope**

- npm ecosystem (`package.json`, `package-lock.json` v1/v2/v3)
- **Direct** dependencies (`dependencies` + `devDependencies`) **and transitive**
  packages discovered in the lock file tree (exact installed versions, including
  nested copies at different versions)
- Public GitHub repositories (web) and local projects (CLI, extension, MCP)
- OSV vulnerability data: ID/CVE, severity, CVSS, fix version, summary — with
  best-effort **NVD cross-referencing** per CVE (second CVSS opinion, rate-limit aware)
- Exploit intelligence on findings: **CISA KEV** (known-exploited, with a
  "newly added" freshness marker), optional **VulnCheck KEV** (wider catalog,
  `VULNCHECK_API_KEY`), **EPSS** (exploit probability), and **public PoC counts**
  (nomi-sec PoC-in-GitHub) — these drive the Fixly Score and CI gates
- Per-package **verdicts** (SAFE/CAUTION/BLOCK): known-malware (`MAL-*`) records,
  nonexistent names (AI-hallucination signal), typosquat/slopsquat detection,
  registry health (age, downloads, deprecation, install scripts), and an optional
  ONNX name-risk model
- A deterministic A–F **Fixly Score** per scan, with the top fixes ranked by points recovered
- Structured, severity-sorted reports; SARIF 2.1.0 output; scan-over-scan
  **history & deltas** in the browser (localStorage — no accounts, no server storage)
- In-editor **inline diagnostics** on `package.json`, **on-save** (and opt-in **as-you-type**)
  **rescans**, a live status-bar indicator, and a one-click **Apply Remediation Plan** with a
  diff preview and Grade Forecast (VS Code extension)

**Out of scope (for now)**

- Scanning live/deployed websites or arbitrary URLs
- Private repositories, authentication
- Other ecosystems (PyPI, Maven, …), auto-fixing, server-side persistence

---

## Repository structure

A [pnpm](https://pnpm.io) workspace orchestrated by [Turborepo](https://turborepo.com):

```
fixly/
├── apps/
│   ├── web/          @fixly/web    — Next.js 16 web scanner
│   ├── cli/          fixly-cli     — CLI (bin: fixly): vibecheck, scan, check, guard
│   ├── mcp/          fixly-mcp     — MCP server (stdio) for AI coding agents
│   └── extension/    fixly-vscode  — VS Code extension
├── packages/
│   ├── core/         @fixly/core   — the scanner + verdict engine (GitHub fetch, parsing,
│   │                                 OSV, NVD, KEV/EPSS intel, typosquat, grade, ONNX inference)
│   └── ui/           @fixly/ui     — shared React UI (Badge + severity helpers)
├── ml/               — Python ML lab (not a workspace package): trains the name-risk
│                       model on OSV malware data, exports ONNX for Node inference
├── examples/         — manifest-only demo projects for the CLI (vulnerable F / clean A)
├── docs/             — architecture & development notes, project plan
├── turbo.json        — task pipeline
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

See [docs/architecture.md](docs/architecture.md) for the data flow.

---

## How it works

### Shared core — `@fixly/core`

All scanning and verdict logic lives here so no surface ever duplicates it.

**Scan pipeline** (web report, `fixly scan`/`vibecheck`, extension, MCP `scan_project`):

1. `parseGitHubUrl` / `fetchProject` — locate and download `package.json` / `package-lock.json`
   (web), or read them from disk (CLI / extension / MCP).
2. `parseDependencies` — resolve direct dependencies to concrete versions (lock file preferred)
   **and walk the full lock tree for transitive packages**, with warnings for a missing lock file
   or unresolvable ranges.
3. `queryOsvBatch` — ask OSV which package@version pairs are vulnerable, then fetch full records
   (see [docs/vulnerability-sources.md](docs/vulnerability-sources.md)).
4. `normalizeOsvResults` — produce a clean `ScanVulnerability` (severity, CVSS, CVE, fix version,
   direct/transitive origin; `MAL-*` records are flagged malicious).
5. `enrichWithNvd` — best-effort NVD cross-reference per CVE (independent CVSS score; degrades to
   a warning under rate limits, never fails a scan).
6. `enrichWithIntel` — stamps CISA KEV (exploited in the wild) and EPSS (exploit probability)
   onto findings; best-effort, cached.
7. `scanProjectFiles` / `runScan` — orchestrate the above and return a severity-sorted `ScanResult`.
8. `computeGrade` — the **Fixly Score**: deterministic point arithmetic over the findings
   (malware = automatic F, KEV and high-EPSS findings weigh extra) plus the top three fixes
   with copy-paste commands.

**Verdict engine** (`fixly check`, `fixly guard`, MCP `check_package`):

`checkPackage(name, version?)` combines OSV malware records, npm registry health
(exists? age? downloads? deprecated? install scripts?), typosquat/slopsquat string analysis
against a popular-package corpus, KEV/EPSS, and an optional ONNX **name-risk model**
(trained in `ml/`, runs via `onnxruntime-node`, falls back to rules when absent) into a
single SAFE/CAUTION/BLOCK verdict with plain-English reasons. A nonexistent package name is
a BLOCK — that's the AI-hallucination (slopsquatting) defense.

### Web app — `@fixly/web`

Submit a public GitHub URL on the dashboard. A Next.js **Server Component** runs `runScan()` from
`@fixly/core` on the server and renders the report (Fixly Score card, summary cards, exploit-intel
markers, warnings, findings table with direct/transitive filter, raw JSON). There is also a
`POST /api/scan` endpoint for programmatic use. Scan history and deltas live in browser
localStorage only.

Supported URL formats:

- `https://github.com/owner/repo`
- `github.com/owner/repo` (protocol optional)
- `https://github.com/owner/repo/tree/<branch>`
- `https://github.com/owner/repo/tree/<branch>/<subfolder>`

Invalid or non-GitHub URLs, missing repos or branches, private repos, and repos
without a `package.json` each return a clear, specific error.

### CLI — `fixly-cli` (bin: `fixly`)

```bash
fixly vibecheck                      # A–F grade for the project in cwd + the fixes that matter
fixly vibecheck --fail-under B       # CI gate: exit 1 if the Fixly Score is below B
fixly scan --sarif > fixly.sarif     # SARIF 2.1.0 for code-scanning UIs
fixly scan --fail-on high            # CI gate (malware always fails a gate)
fixly check lodahs                   # SAFE/CAUTION/BLOCK — catches the typo before install
fixly guard -- npm install <pkgs>    # verdict-check the named packages, then run the install
```

Zero runtime dependencies, esbuild-bundled. Exit codes are scriptable
(0 ok · 1 gate/caution · 2 error/block). Not yet published to npm — run it from this
repo (`pnpm build`, then `node apps/cli/dist/cli.js`).

### MCP server — `fixly-mcp`

An MCP (Model Context Protocol) server over stdio that lets AI coding agents ask
"is this package safe?" before adding a dependency. Tools return compact, verdict-shaped
JSON (never raw finding dumps — agent context is scarce). See [apps/mcp/README.md](apps/mcp/README.md)
for setup with Claude Code.

### VS Code extension — `fixly-vscode`

The **Fixly: Scan Current Project** command reads the open workspace's manifest files and calls the
same `@fixly/core` scanner, then renders a webview report (Fixly Score, a **Grade Forecast** line
with an **Apply Fix Plan** button, summary cards, findings table, warnings, and
**Rescan / Copy Summary / Export JSON** actions). Vulnerable **direct** dependencies get inline
diagnostics on `package.json`; saving `package.json`/`package-lock.json` triggers a debounced rescan
(`fixly.scanOnSave`), and editing it rescans from the unsaved buffer when `fixly.scanOnType` is on;
a status-bar item shows live severity counts and the forecast grade. **Fixly: Apply Remediation
Plan** (`fixly.applyRemediationPlan`) writes the fix plan into `package.json` (direct upgrades +
transitive `overrides`) behind a side-by-side diff preview and a confirmation, listing malware
`npm uninstall` commands to run by hand. An optional `fixly.nvdApiKey` supplies an NVD key for wider
CVE coverage.

### ML lab — `ml/`

A standalone Python project (not part of the pnpm workspace). `python -m fixly_ml.dataset` builds a
labeled corpus (real OSV `MAL-*` malicious names vs. popular npm names); `python -m fixly_ml.train`
trains a scaled-MLP pipeline and exports `ml/models/name-risk.onnx` + a feature manifest. The model
is committed, so Node inference works from a clean checkout. Feature extraction is a hard contract
between `ml/fixly_ml/features.py` and `packages/core/src/name-model.ts`, pinned by paired tests on
both sides. Scope is honest: a name-only model is **one weak corroborating signal**, never a verdict
by itself — see [ml/README.md](ml/README.md).

---

## Development

Requires Node 20 (pinned in [.nvmrc](.nvmrc); CI uses Node 20) and pnpm. **Use pnpm only** (there is no `package-lock.json`).

```bash
pnpm install      # install all workspace dependencies
pnpm dev          # run the web app at http://localhost:3000
pnpm build        # build the web app + bundle the CLI, MCP server, and extension
pnpm lint         # lint every package
pnpm typecheck    # type-check every package
pnpm test         # run the test suite (Vitest: packages/core, apps/cli, apps/mcp, apps/web)
```

Scope to a single package with `--filter`, e.g.:

```bash
pnpm --filter @fixly/core test
pnpm --filter fixly-vscode build
```

ML lab (optional; only needed to retrain the model):

```bash
cd ml
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt      # (POSIX: .venv/bin/pip)
.venv\Scripts\python -m pytest tests -q            # feature-parity tests (also run in CI)
```

### GitHub token (optional)

Unauthenticated GitHub requests are rate-limited (~60/hour). To raise the limit,
set a **server-side** `GITHUB_TOKEN` (see [.env.example](.env.example)) — copy it
to `apps/web/.env.local` for the web app, or export it before `pnpm validate`. It
is never exposed to the client.

### Validation

```bash
pnpm validate   # runs scripts/validate.ts against live GitHub + OSV (see validation-notes.md)
```

More detail in [docs/development.md](docs/development.md).

---

## Current limitations

- Unauthenticated GitHub requests are rate-limited (~60/hour); large or repeated scans can hit the limit.
- Transitive discovery requires a `package-lock.json` — without a lock file the scan is direct-only
  (with a warning). yarn/pnpm lock files are not parsed.
- Vulnerabilities without a CVSS vector or database severity are shown as **Unknown** — Fixly never
  invents a score.
- NVD **enriches** findings that carry a CVE; it never detects on its own, and public rate limits
  mean partial coverage is normal (the report states exactly how many CVEs were covered).
- `fixly guard` checks the packages **named on the command line**; a bare lockfile install passes
  through (run `fixly vibecheck` after those).
- The CLI and MCP server are not yet published to npm; the extension is not on the marketplace.
  Everything runs from this repo.

---

## Team

- Jibril Abdi — documentation, README, reporting
- Warsame Abdi — architecture, scanner logic, API integration, repo scanning workflow
- Riyadh Al-Hoyidy — OSV/NVD research, CVE matching validation, report/UI polish

---

## License

[MIT](LICENSE).
