# Fixly Capstone Demo Runbook

Last verified: 2026-08-05.

This runbook reflects the current implementation on `feat/extension-demo-finalization`.
Fixly is advice-only: it scans, reports, copies remediation advice, and verifies
external changes. It does not edit scanned projects or run package installs.

## A. Demo-ready capabilities

| Feature | Verified live? | Surface | Exact action | Live-demo recommendation |
| ------- | -------------- | ------- | ------------ | ------------------------ |
| Web GitHub repository scan | Ready with setup | Web dashboard at `http://localhost:3000/dashboard` | Paste a public GitHub URL and click `Scan repo` | Use only if internet is stable; otherwise use the bundled sample scan. |
| Fixly Score | Ready | Web report, VS Code report, CLI `vibecheck` / `fix` | Open a completed report or run `fixly vibecheck` | Show in web or VS Code report as the headline metric. |
| Severity summary | Ready | Web report, VS Code report, status bar | Complete a scan | Point to counts, not every row. |
| Vulnerability details | Ready | Web findings table, VS Code report, hover | Open report or hover a dependency | Show one direct dependency only. |
| Remediation plan | Ready | Web report, VS Code report, CLI `fix` | Open report or run `fixly fix <dir>` | Use VS Code report for the live demo. |
| VS Code scan | Ready | VS Code Command Palette | `Fixly: Scan Current Project` | Primary live demo path. |
| Status bar | Ready | VS Code status bar | Click the `Fixly` status-bar item after a scan | Show the scan counts, then click it to reopen the report. |
| Diagnostics | Ready | VS Code `package.json` editor | Scan the fixture and open `package.json` | Point to `minimist` squiggle. |
| Hover card | Ready | VS Code `package.json` editor | Hover over `minimist` | Use this to explain installed version, severity, and safe target. |
| Report panel | Ready | VS Code webview titled `Fixly Report` | Run `Fixly: Scan Current Project` or `Fixly: Show Last Report` | Main explanation surface. |
| Complete Fix Brief | Ready | Command Palette | `Fixly: Copy Complete Fix Brief` | Mention briefly; do not paste the whole complete brief live. |
| Per-package Fix Brief | Ready | VS Code lightbulb/code action | `Fixly: Copy Fix Brief for minimist` | Paste this brief into a temp text file live. |
| Lockfile verification | Ready | VS Code package-lock watcher | Run `npm install minimist@1.2.6` in the fixture | Strongest differentiator; include it. |
| Resolved findings | Ready | VS Code notification/output after lockfile rescan | External lockfile update | Expect `2 resolved`. |
| Still-present findings | Ready | VS Code notification/output after lockfile rescan | External lockfile update | Expect `10 still present`. |
| Newly introduced findings | Ready | VS Code notification/output after lockfile rescan | External lockfile update | Do not force new findings live; mention the classifier supports it. |
| CLI | Ready | Terminal | `node C:\Users\Diomio\Desktop\fixly\apps\cli\dist\cli.js fix C:\Users\Diomio\Desktop\fixly-demo-fixture` | Backup only; it is less visual than VS Code. |
| MCP | Ready with setup | MCP stdio server | Tools: `check_package`, `scan_project`, `suggest_safe_alternative` | Not worth showing in a 3-minute demo unless asked. |

## B. Recommended Demo

Use this 2.5-to-3-minute flow:

1. Open `C:\Users\Diomio\Desktop\fixly-demo-fixture` in normal VS Code.
2. Open `package.json`.
3. Run `Fixly: Scan Current Project`.
4. Show scan progress and the status-bar result.
5. Point to the direct-dependency diagnostic on `minimist`.
6. Hover over `minimist`.
7. Open the full report with `Fixly: Show Last Report` or the status bar.
8. Explain installed version `1.2.0`, identifiers `GHSA-xvch-5gv4-984h` and `GHSA-vh95-rmgr-6w4m`, critical/medium severity, safe target `1.2.6`, low patch risk, and rationale.
9. Use `Fixly: Copy Fix Brief for minimist`.
10. Paste the brief into a temporary text file.
11. Manually update the dependency outside Fixly by running `npm install minimist@1.2.6`.
12. Let the lockfile watcher rescan.
13. Show the verification summary: `Fixly verification: 2 resolved, 10 still present, 0 new findings introduced.`
14. Say: "Fixly advised and verified, but it never modified the project."

## C. Exact click-by-click instructions

## Step 1 - Open the vulnerable fixture

Presenter:
Riyadh

Window:
Normal VS Code, not Extension Development Host.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
`File` -> `Open Folder...` -> select `C:\Users\Diomio\Desktop\fixly-demo-fixture`.

Keyboard shortcut:
None.

Expected result:
Explorer shows `package.json`, `package-lock.json`, and `node_modules`.

Point to:
The root `package.json`.

Say:
"This is a tiny npm project with two deliberately old direct dependencies."

Time:
10 seconds.

Fallback:
If VS Code opens the repo instead, use `File` -> `Open Folder...` again and choose the fixture path.

## Step 2 - Open package.json

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Explorer -> `package.json`.

Keyboard shortcut:
None.

Expected result:
`dependencies` shows `"lodash": "^4.17.4"` and `"minimist": "^1.2.0"`.

Point to:
The `minimist` dependency line.

Say:
"Fixly reads the manifest and the npm lockfile, so these are exact installed versions."

Time:
10 seconds.

Fallback:
Use `Ctrl+P`, type `package.json`, press `Enter`.

## Step 3 - Run the scan

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
None.

Keyboard shortcut:
`Ctrl+Shift+P`, type `Fixly: Scan Current Project`, press `Enter`.

Expected result:
A progress notification says `Fixly: scanning dependencies...`; the `Fixly Report` webview opens.

Point to:
The notification first, then the report title.

Say:
"This is an on-demand scan against OSV, with NVD as enrichment when available."

Time:
20 seconds.

Fallback:
If the command is missing, confirm the installed extension is `fixly.fixly-vscode@0.2.0`.

## Step 4 - Show the status bar

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Bottom status bar item starting with `Fixly:`.

Keyboard shortcut:
None.

Expected result:
The status bar shows critical/high/medium counts such as `Fixly: 2C 4H 6M`, and clicking opens the report.

Point to:
The bottom status bar.

Say:
"The editor stays lightweight: the status bar gives the current security shape at a glance."

Time:
10 seconds.

Fallback:
Run `Fixly: Show Last Report`.

## Step 5 - Show diagnostics

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
`package.json` editor tab.

Keyboard shortcut:
None.

Expected result:
Direct dependencies have Fixly diagnostics. `minimist` is marked because it has two findings.

Point to:
The squiggle/Problems marker on `minimist`.

Say:
"Only direct dependencies get editor diagnostics because those have lines in package.json. Transitives stay in the report."

Time:
10 seconds.

Fallback:
Close and reopen `package.json`, then run `Fixly: Scan Current Project` again.

## Step 6 - Show the hover card

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Hover the mouse over `minimist`.

Keyboard shortcut:
None.

Expected result:
Hover shows `minimist@1.2.0`, two advisories, worst severity critical, and remediation advice.

Point to:
Installed version, vulnerability IDs, and safe target.

Say:
"The hover is remediation-aware: it explains the finding and the safe target without changing the file."

Time:
20 seconds.

Fallback:
Use the report panel if the hover is slow to appear.

## Step 7 - Open the full report

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Status bar `Fixly:` item.

Keyboard shortcut:
Alternative: `Ctrl+Shift+P`, type `Fixly: Show Last Report`, press `Enter`.

Expected result:
`Fixly Report` opens beside the editor.

Point to:
Fixly Score, Grade Forecast, Remediation Plan, and findings table.

Say:
"The full report combines severity, exploit context, safe target, and remediation risk."

Time:
20 seconds.

Fallback:
Run `Fixly: Scan Current Project` again.

## Step 8 - Explain minimist

Presenter:
Riyadh

Window:
VS Code report panel.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Scroll to `minimist` in the Remediation Plan or findings table.

Keyboard shortcut:
None.

Expected result:
The report shows `minimist 1.2.0 -> 1.2.6` and the two minimist findings.

Point to:
`GHSA-xvch-5gv4-984h`, `CVE-2021-44906`, severity `critical`, and fix `1.2.6`.

Say:
"For minimist, Fixly found prototype pollution, identified the installed version as 1.2.0, and recommends the minimum safe patch release, 1.2.6."

Time:
20 seconds.

Fallback:
Use `Ctrl+F`, search `minimist`.

## Step 9 - Copy the per-package Fix Brief

Presenter:
Riyadh

Window:
VS Code `package.json` editor.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Place cursor on `minimist`; click the lightbulb; choose `Fixly: Copy Fix Brief for minimist`.

Keyboard shortcut:
Alternative: `Ctrl+.` while cursor is on `minimist`.

Expected result:
Notification: `Fixly: fix brief for minimist copied - paste it to a teammate or coding agent.`

Point to:
The lightbulb action label.

Say:
"This copies precise advice only. It does not edit package.json."

Time:
15 seconds.

Fallback:
Use Command Palette `Fixly: Copy Complete Fix Brief` and explain the complete brief instead.

## Step 10 - Paste the brief

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
`File` -> `New Text File`, then click into the editor.

Keyboard shortcut:
`Ctrl+V`.

Expected result:
The pasted brief names `minimist@1.2.0`, advisories, target `1.2.6`, semver jump `PATCH`, risk `low`, and says to run `npm install` and rescan.

Point to:
Minimum safe target and final advice-only sentence.

Say:
"This is what a teammate or coding agent can safely act on."

Time:
20 seconds.

Fallback:
If clipboard is empty, repeat Step 9.

## Step 11 - Apply the external change manually

Presenter:
Riyadh

Window:
Integrated terminal in the fixture.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
`Terminal` -> `New Terminal`.

Keyboard shortcut:
Type `npm install minimist@1.2.6` and press `Enter`.

Expected result:
npm changes one package and rewrites `package.json` / `package-lock.json`.

Point to:
The terminal command, not Fixly.

Say:
"Now I make the change myself with npm. Fixly is not running this command."

Time:
25 seconds.

Fallback:
If npm is slow, stop here and show the backup video from the same step.

## Step 12 - Show lockfile verification

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
Watch the bottom-right notification or open Output -> `Fixly`.

Keyboard shortcut:
None.

Expected result:
`Fixly verification: 2 resolved, 10 still present, 0 new findings introduced.`

Point to:
The notification, then the Fixly output channel details.

Say:
"Fixly detected the lockfile change, rescanned, and verified exactly what changed."

Time:
20 seconds.

Fallback:
Run `Fixly: Scan Current Project`; if the notification is missed, open Output -> `Fixly`.

## Step 13 - Close the VS Code section

Presenter:
Riyadh

Window:
VS Code fixture window.

Folder:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Click:
None.

Keyboard shortcut:
None.

Expected result:
Report still shows lodash findings after minimist is fixed.

Point to:
Remaining lodash findings.

Say:
"The important point is not that everything vanished. Fixly tells us what was resolved, what remains, and whether our change introduced anything new."

Time:
15 seconds.

Fallback:
Use CLI: `node C:\Users\Diomio\Desktop\fixly\apps\cli\dist\cli.js scan C:\Users\Diomio\Desktop\fixly-demo-fixture --json`.

## D. Exact Fixture

Exact path:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

`package.json` dependencies:

```json
{
  "lodash": "^4.17.4",
  "minimist": "^1.2.0"
}
```

Installed vulnerable versions:
`lodash@4.17.4`, `minimist@1.2.0`.

Lockfile version:
`3`.

Number of findings at reset:
`12` total: `10` for `lodash`, `2` for `minimist`.

Best direct dependency to demonstrate:
`minimist`.

Its vulnerability identifiers:
`GHSA-xvch-5gv4-984h` / `CVE-2021-44906` and `GHSA-vh95-rmgr-6w4m` / `CVE-2020-7598`.

Installed version:
`1.2.0`.

Minimum safe target:
`1.2.6`.

Exact manual change:
Run `npm install minimist@1.2.6` in `C:\Users\Diomio\Desktop\fixly-demo-fixture`.

Exact `npm install` command:

```powershell
npm install minimist@1.2.6
```

Expected verification result:
`Fixly verification: 2 resolved, 10 still present, 0 new findings introduced.`

Note:
Fixly also recommends `lodash 4.17.4 -> 4.18.0`, but npm currently marks `lodash@4.18.0` deprecated as a bad release. Do not use lodash for the live manual update.

## E. Presenter Split

Warsame - maximum 55 seconds

Exact actions:
Open `http://localhost:3000/dashboard`, click `Try a sample scan`, show the report summary, Fixly Score, severity summary, and findings table.

Exact speaking lines:
"Fixly starts from a simple question: what is vulnerable in this npm project? The web dashboard scans a public repo or the built-in sample, shows the Fixly Score, and organizes findings by severity with the exact package and advisory IDs."

Handoff sentence:
"Jibril will show why the recommendation is not just a version number."

Jibril - maximum 55 seconds

Exact actions:
On the web or VS Code report, point to one OSV finding, its CVE, CVSS/NVD enrichment if present, dependency type, fixed version, and remediation rationale.

Exact speaking lines:
"OSV is the detection source. NVD is enrichment. Fixly then checks the installed version and dependency graph to recommend the minimum safe target and explain the risk, including blocked or no-fix cases when they are real."

Handoff sentence:
"Riyadh will show the same intelligence inside the editor and prove the verification loop."

Riyadh - maximum 80 seconds

Exact actions:
Run `Fixly: Scan Current Project`, show `minimist` diagnostic, hover, copy `Fixly: Copy Fix Brief for minimist`, paste it, run `npm install minimist@1.2.6`, show verification.

Exact speaking lines:
"Inside VS Code, Fixly gives diagnostics and hover cards directly on package.json. The Fix Brief copies advice for a human or coding agent. I run npm myself, and Fixly verifies the lockfile change afterward."

Handoff sentence:
"That is the product boundary: Fixly advises and verifies; the developer remains in control."

## F. Backup Plan

What should already be open:
Normal VS Code with `C:\Users\Diomio\Desktop\fixly-demo-fixture`, browser at `http://localhost:3000/dashboard/results?fixture=vulnerable-demo`, and a terminal in the fixture folder.

Local backup-video sequence:
Record Steps 1 through 13 after resetting the fixture. Save the video as `C:\Users\Diomio\Desktop\fixly-demo-backup.mp4`.

Screenshots to capture:
Command Palette with `Fixly: Scan Current Project`; `minimist` diagnostic; `minimist` hover card; VS Code report remediation plan; pasted Fix Brief; verification notification; web sample report summary.

Exact video pause points:
Pause after the scan result opens, after the hover card appears, after the Fix Brief is pasted, and after the verification notification appears.

What each presenter says:
Warsame narrates detection and report layout. Jibril narrates OSV, NVD, safe target, and risk. Riyadh narrates VS Code diagnostic, Fix Brief, manual npm install, and verification.

Recovery if OSV is slow:
Use the web bundled sample at `http://localhost:3000/dashboard/results?fixture=vulnerable-demo` or play the backup video from the scan-result pause.

Recovery if the web fails:
Skip Warsame's browser flow and use the VS Code report panel plus CLI `fix` output.

Recovery if VS Code fails:
Use CLI commands from the fixture:

```powershell
node C:\Users\Diomio\Desktop\fixly\apps\cli\dist\cli.js fix C:\Users\Diomio\Desktop\fixly-demo-fixture
npm install minimist@1.2.6
node C:\Users\Diomio\Desktop\fixly\apps\cli\dist\cli.js scan C:\Users\Diomio\Desktop\fixly-demo-fixture --json
```

Recovery if neither works:
Use the backup video and screenshots. The narration must still cover detection, analysis, remediation advice, and verification.

## G. Practice Reset Instructions

Run all reset commands in `C:\Users\Diomio\Desktop\fixly-demo-fixture`, never in the Fixly monorepo.

Files to restore:
`package.json` and `package-lock.json`.

Dependency versions:
`lodash@4.17.4`, `minimist@1.2.0`.

Delete `node_modules`?
No for normal practice. Delete only if npm behaves oddly.

Regenerate `package-lock.json`?
Yes, by running npm in the fixture.

Exact reset commands:

```powershell
cd C:\Users\Diomio\Desktop\fixly-demo-fixture
npm install lodash@4.17.4 minimist@1.2.0
```

Hard reset if the fixture gets messy:

```powershell
cd C:\Users\Diomio\Desktop\fixly-demo-fixture
Remove-Item -Recurse -Force node_modules
Remove-Item -Force package-lock.json
npm install lodash@4.17.4 minimist@1.2.0
```

How to verify the fixture is vulnerable again:

```powershell
node C:\Users\Diomio\Desktop\fixly\apps\cli\dist\cli.js scan C:\Users\Diomio\Desktop\fixly-demo-fixture --json
```

Expected vulnerable result:
`12` findings total: `10` lodash and `2` minimist.

How to ensure fixture files are not committed to Fixly:
Keep the fixture outside the repo at `C:\Users\Diomio\Desktop\fixly-demo-fixture`. Before committing in Fixly, run `git status -sb` from `C:\Users\Diomio\Desktop\fixly` and confirm no fixture files appear.

## H. One-page Cheat Sheet

Fixture path:
`C:\Users\Diomio\Desktop\fixly-demo-fixture`

Web URL:
`http://localhost:3000/dashboard/results?fixture=vulnerable-demo`

VS Code command:
`Fixly: Scan Current Project`

Best package:
`minimist`

Installed version:
`1.2.0`

Safe version:
`1.2.6`

Fix Brief action:
Lightbulb on `minimist` -> `Fixly: Copy Fix Brief for minimist`

Manual update:
Update outside Fixly using npm in the fixture terminal.

Install command:
`npm install minimist@1.2.6`

Expected verification message:
`Fixly verification: 2 resolved, 10 still present, 0 new findings introduced.`

Presenter handoffs:
Warsame: "Jibril will show why the recommendation is not just a version number."
Jibril: "Riyadh will show the same intelligence inside the editor and prove the verification loop."
Riyadh: "That is the product boundary: Fixly advises and verifies; the developer remains in control."

Backup-video path:
`C:\Users\Diomio\Desktop\fixly-demo-backup.mp4`

Emergency fallback order:
VS Code live demo -> web sample report -> CLI fixture commands -> backup video -> screenshots.
