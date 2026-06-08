# VS Code extension — manual QA checklist

The extension is an on-demand prototype; these steps are run by hand in an
Extension Development Host. Build first:

```bash
pnpm --filter fixly-vscode build
```

Then open `apps/extension` in VS Code and press <kbd>F5</kbd>.

## Setup

- [ ] Extension activates without errors (check the "Fixly" output channel).
- [ ] Command **Fixly: Scan Current Project** appears in the Command Palette.

## Happy path (vulnerable project)

- [ ] Open a folder containing a `package.json` with known-vulnerable deps
      (e.g. a clone of `OWASP/NodeGoat`).
- [ ] Run **Fixly: Scan Current Project**.
- [ ] A progress notification shows while scanning.
- [ ] A "Fixly Report" webview opens with:
  - [ ] summary cards: dependencies, vulnerabilities, critical/high/medium/low/unknown
  - [ ] a findings table: package, installed version, ID, CVE, severity, CVSS, summary, fix
  - [ ] the scanned target line (folder name, files found)
- [ ] The "Fixly" output channel logs the files loaded and the scan result.

## Webview actions

- [ ] **Rescan Project** re-runs the scan and refreshes the report.
- [ ] **Copy Summary** copies a text summary to the clipboard (confirmation toast).
- [ ] **Export JSON Report** opens a save dialog and writes a valid JSON file.

## Edge cases

- [ ] Folder with `package.json` but no `package-lock.json` → report shows the
      "approximate versions" warning, scan still completes.
- [ ] Folder with no `package.json` → a clear warning message, no crash.
- [ ] No folder open → a clear warning message.
- [ ] Clean project (no known vulns) → report shows zero vulnerabilities.

## Reliability

- [ ] Offline / network blip → the scan reports an OSV failure cleanly (no
      unhandled exception); retries happen under the hood.
- [ ] A repo with many vulnerabilities completes without hanging (OSV detail
      requests are concurrency-limited).

> Record the VS Code version and OS used, and attach a screenshot of the report
> webview to the PR when running this checklist.
