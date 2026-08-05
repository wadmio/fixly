# Fixly — VS Code extension

Scan the open project's npm dependencies — direct **and transitive** — for
known vulnerabilities, using the shared [`@fixly/core`](../../packages/core)
scanner (OSV detection + NVD CVE cross-referencing).

**Fixly analyzes and verifies, never modifies.** It computes deterministic,
graph-accurate remediation intelligence — the minimum safe target version
checked against your real `package-lock.json` dependency graph, the resolution
path, the semver jump size, and why — and hands it to you (or your AI agent)
as precise advice. It never edits `package.json` and never runs installs; the
manifest watcher then verifies outcomes on the next scan.

## Commands

- **Fixly: Scan Current Project** (`fixly.scanCurrentProject`) — reads
  `package.json` and `package-lock.json` from the first workspace folder,
  resolves the full dependency tree, queries OSV (+ NVD), and opens a report.
- **Fixly: Show Last Report** (`fixly.showReport`) — re-opens the report panel
  (also what clicking the status bar item does).

## In-editor feedback

- **Inline diagnostics** — every vulnerable *direct* dependency gets a squiggle
  on its exact line in `package.json` (critical/high → error, medium → warning,
  low → info), with the worst CVE, the finding count, and the fix version in
  the hover; the diagnostic code links to the advisory. Findings also appear in
  the Problems panel. Transitive findings live in the report panel (they have
  no line in `package.json` to point at).
- **Status bar** — live severity counts after every scan (e.g.
  `Fixly: 2C 5H 3M`), red background when critical/high findings exist,
  `Fixly: clean` when there are none. The tooltip shows the **Grade Forecast** —
  the grade you'd reach by applying the fix plan. Click to open the report.
- **Scan on change** — saving `package.json` / `package-lock.json` in the
  editor **or** an external write to them (npm rewriting the lock file during
  `npm install`) triggers an automatic, quiet rescan (shared 1.2s debounce, so
  a burst of writes scans once). Toggle with `fixly.scanOnSave`.
- **Scan as you type** (opt-in) — with `fixly.scanOnType` enabled, editing
  `package.json` rescans from the **unsaved** editor buffer (1.5s debounce), no
  save required; the saved `package-lock.json` still supplies the tree.

## Settings

| Setting | Default | Effect |
|---|---|---|
| `fixly.scanOnSave` | `true` | Rescan automatically when `package.json` / `package-lock.json` changes (editor saves and external writes, e.g. `npm install`). |
| `fixly.scanOnType` | `false` | Rescan as you type in `package.json`, from the unsaved buffer (debounced). |
| `fixly.includeTransitive` | `true` | Walk the `package-lock.json` tree for transitive packages. |
| `fixly.nvdApiKey` | `""` | NVD API key to widen CVE cross-referencing (see [NVD API key](#nvd-api-key-optional)). |

## NVD API key (optional)

NVD's public API is rate-limited (~5 requests / 30s), so a large project only
gets a handful of CVEs cross-referenced per scan. A **free** key raises the
limit — and Fixly then fetches concurrently for wider coverage:

1. Request one at <https://nvd.nist.gov/developers/request-an-api-key> — free,
   emailed to you in a minute.
2. Put it in **`fixly.nvdApiKey`** (Settings → Extensions → Fixly), or export
   `NVD_API_KEY` in the environment VS Code launches from.

Prefer VS Code **User** settings so the key stays out of your repository. It is
masked in the **Fixly** output channel and only ever sent to NVD.

## Report

A webview panel shows:

- The **Fixly Score** (A–F) with the top fixes, and a **Grade Forecast** line —
  the grade you'd reach by applying the fix plan (e.g. "Fix per the plan below →
  B (86), +34 points").
- The **Remediation Plan**: one advice entry per fixable package — installed →
  target version with a risk chip (`patch`/`minor` calm; `major`/`override`
  elevated; malware distinct), the engine's rationale, and a copy-paste
  command. A **Blocked** card explains fixes a parent's version range forbids
  (which parent, which range, what would unblock), and findings with no
  published fix are listed as such — both are legitimate states, not errors.
- Summary cards: packages (direct + transitive), total vulnerabilities, and
  per-severity counts (critical / high / medium / low / unknown).
- A findings table: package (with a `transitive` chip where relevant),
  installed version, OSV ID + data sources, CVE, severity, CVSS (with NVD's
  independent score when cross-referenced), summary, and fix version.
- Warnings (missing lock file, unresolved versions, partial OSV/NVD data).
- Actions: **Rescan Project**, **Copy Summary**, **Export JSON Report**.

The panel refreshes in place after on-save rescans. Diagnostic logs are written
to the **Fixly** output channel.

## Develop

```bash
pnpm --filter fixly-vscode build         # bundle to dist/extension.js (esbuild)
pnpm --filter fixly-vscode typecheck
pnpm --filter fixly-vscode package:vsix  # build + package fixly-vscode-<version>.vsix
```

Then press <kbd>F5</kbd> in VS Code (Extension Development Host) to run it, or
install the packaged build with "Extensions: Install from VSIX". To ship a
release, bump `version` in package.json, package, and publish (needs the
`fixly` publisher's Marketplace PAT):

```bash
npx vsce publish --packagePath fixly-vscode-<version>.vsix
```

## Scope

Published to the VS Code Marketplace as `fixly.fixly-vscode`. No auth, npm
only — same scope as the rest of Fixly. Transitive scanning requires a
`package-lock.json` in the workspace.

**Fixly analyzes and verifies, never modifies.** The extension writes no files
and launches no processes: remediation output is advice — exact target
versions, override entries, copy-paste commands — for you or your AI agent to
apply. After you make a change and your package manager rewrites the lock
file, Fixly rescans automatically and reports what actually got fixed.
