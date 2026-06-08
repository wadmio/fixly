# Fixly

## Dependency Vulnerability Detection for Modern Web Applications

Fixly helps developers find vulnerable third-party **npm** dependencies. It does **not** scan live
websites — it scans a project's dependency manifests (`package.json` / `package-lock.json`) and
checks each installed version against the [OSV](https://osv.dev) vulnerability database.

Fixly ships two surfaces over one shared scanner:

- **Web scanner** — paste a public GitHub repo URL and get a vulnerability report.
- **VS Code extension** — scan the project you have open, in-editor.

---

## Product scope

**In scope**

- npm ecosystem (`package.json`, `package-lock.json` v1/v2/v3)
- **Direct** dependencies (`dependencies` + `devDependencies`)
- Public GitHub repositories (web) and the local workspace (extension)
- OSV vulnerability data: ID/CVE, severity, CVSS, fix version, summary
- Structured, severity-sorted reports

**Out of scope (for now)**

- Scanning live/deployed websites or arbitrary URLs
- Transitive / nested dependencies
- Private repositories, authentication
- Other ecosystems (PyPI, Maven, …), NVD, CI/CD gating, auto-fixing, persistence

---

## Repository structure

A [pnpm](https://pnpm.io) workspace orchestrated by [Turborepo](https://turborepo.com):

```
fixly/
├── apps/
│   ├── web/          @fixly/web    — Next.js 16 web scanner
│   └── extension/    fixly-vscode  — VS Code extension prototype
├── packages/
│   ├── core/         @fixly/core   — shared scanner (GitHub fetch, parsing, OSV, normalization)
│   └── ui/           @fixly/ui     — shared React UI (Badge + severity helpers)
├── docs/             — architecture & development notes, project plan
├── turbo.json        — task pipeline
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

See [docs/architecture.md](docs/architecture.md) for the data flow.

---

## How it works

### Shared core — `@fixly/core`

All scanning logic lives here so the web app and the extension never duplicate it.

1. `parseGitHubUrl` / `fetchProjectFiles` — locate and download `package.json` / `package-lock.json`.
2. `parsePackages` — resolve direct dependencies to concrete versions (lock file preferred), with warnings for a missing lock file or unresolvable ranges.
3. `queryOsvBatch` — ask OSV which packages/versions are vulnerable, then fetch full records (OSV is the only live source — see [docs/vulnerability-sources.md](docs/vulnerability-sources.md)).
4. `normalizeOsvResults` — produce a clean `ScanVulnerability` (severity, CVSS, CVE, fix version).
5. `scanProjectFiles` / `runScan` — orchestrate the above and return a severity-sorted `ScanResult`.

### Web app — `@fixly/web`

Submit a public GitHub URL on the dashboard. A Next.js **Server Component** runs `runScan()` from
`@fixly/core` on the server and renders the report (summary cards, warnings, findings table, raw
JSON). There is also a `POST /api/scan` endpoint for programmatic use.

Supported URL formats:

- `https://github.com/owner/repo`
- `github.com/owner/repo` (protocol optional)
- `https://github.com/owner/repo/tree/<branch>`
- `https://github.com/owner/repo/tree/<branch>/<subfolder>`

Invalid or non-GitHub URLs, missing repos or branches, private repos, and repos
without a `package.json` each return a clear, specific error.

### VS Code extension — `fixly-vscode`

The **Fixly: Scan Current Project** command reads the open workspace's manifest files and calls the
same `@fixly/core` scanner, then renders a webview report (summary cards, findings table, warnings,
and **Rescan / Copy Summary / Export JSON** actions). Diagnostics go to the "Fixly" output channel.

---

## Development

Requires Node 20 (pinned in [.nvmrc](.nvmrc); CI uses Node 20) and pnpm. **Use pnpm only** (there is no `package-lock.json`).

```bash
pnpm install      # install all workspace dependencies
pnpm dev          # run the web app at http://localhost:3000
pnpm build        # build the web app + bundle the extension
pnpm lint         # lint every package
pnpm typecheck    # type-check every package
pnpm test         # run the test suite (Vitest, in packages/core)
```

Scope to a single package with `--filter`, e.g.:

```bash
pnpm --filter @fixly/core test
pnpm --filter fixly-vscode build
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
- Only direct dependencies are analyzed — a vulnerable transitive package is not reported unless it is also a direct dependency.
- Vulnerabilities without a CVSS vector or database severity are shown as **Unknown**.
- The extension is an early prototype: on-demand scanning only (no background scanning, settings, or marketplace packaging).

---

## Team

- Jibril Abdi — documentation, README, reporting
- Warsame Abdi — architecture, scanner logic, API integration, repo scanning workflow
- Riyadh Al-Hoyidy — OSV/NVD research, CVE matching validation, report/UI polish

---

## License

For academic and educational purposes.
