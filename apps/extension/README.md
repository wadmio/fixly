# Fixly — VS Code extension

Scan the open project's npm dependencies — direct **and transitive** — for
known vulnerabilities, using the shared [`@fixly/core`](../../packages/core)
scanner (OSV detection + NVD CVE cross-referencing).

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
  `Fixly: clean` when there are none. Click to open the report.
- **Scan on save** — saving `package.json` or `package-lock.json` triggers an
  automatic, quiet rescan (1.2s debounce, so `npm install` touching both files
  scans once).

## Settings

| Setting | Default | Effect |
|---|---|---|
| `fixly.scanOnSave` | `true` | Rescan automatically when a manifest is saved. |
| `fixly.includeTransitive` | `true` | Walk the package-lock tree for transitive packages. |

## Report

A webview panel shows:

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
pnpm --filter fixly-vscode build      # bundle to dist/extension.js (esbuild)
pnpm --filter fixly-vscode typecheck
```

Then press <kbd>F5</kbd> in VS Code (Extension Development Host) to run it.

## Scope (prototype)

No marketplace packaging, no auth, npm only — same scope as the rest of Fixly.
Transitive scanning requires a `package-lock.json` in the workspace.
