# Fixly — VS Code extension

Scan the open project's npm dependencies for known vulnerabilities, using the
shared [`@fixly/core`](../../packages/core) scanner (OSV data source).

## Command

- **Fixly: Scan Current Project** (`fixly.scanCurrentProject`) — reads
  `package.json` and `package-lock.json` from the first workspace folder,
  resolves direct dependencies, queries OSV, and opens a report.

## Report

A webview panel shows:

- Summary cards: dependencies, total vulnerabilities, and per-severity counts
  (critical / high / medium / low / unknown).
- A findings table: package, installed version, OSV ID, CVE, severity, CVSS,
  summary, and fix version.
- Warnings (missing lock file, unresolved versions, partial OSV data).
- Actions: **Rescan Project**, **Copy Summary**, **Export JSON Report**.

Diagnostic logs are also written to the **Fixly** output channel.

## Develop

```bash
pnpm --filter fixly-vscode build      # bundle to dist/extension.js (esbuild)
pnpm --filter fixly-vscode typecheck
```

Then press <kbd>F5</kbd> in VS Code (Extension Development Host) to run it.

## Scope (prototype)

No background scanning, no settings, no marketplace packaging, no auth. npm
direct dependencies only — same scope as the rest of Fixly.
