# `fixly daemon` — real-time remediation

The daemon inverts Fixly from pull to push. Every other surface scans when you
ask; the daemon reacts when the world changes — and then **fixes the problem
itself**, verifies the fix with a re-scan, and reports the measured
time-to-remediate. It is the "real-time remediation engine": detection,
remediation, and verification in one unattended loop.

```
fixly daemon [dir ...]          watch + auto-remediate project(s); default "."
  --interval <min>              advisory re-scan cadence (default 10, min 1)
  --notify-only                 detect + alert, never touch files
  --no-install                  rewrite package.json but skip `npm install`
  --webhook <url>               POST a JSON event on new/escalated findings
  --no-desktop                  suppress OS desktop notifications
  --json                        newline-delimited JSON events on stdout
```

Foreground process, Ctrl+C to stop. Multiple directories are watched
independently, each with its own state and jittered poll schedule.

## The loop

Two triggers feed one serialized scan path per project:

1. **File changes** — `fs.watch` on `package.json` / `package-lock.json`
   (1s debounce). A vulnerable dependency is detected within ~1 second of
   landing on disk, however it got there (editor save, `npm install`, an AI
   agent editing the manifest).
2. **The advisory clock** — every `--interval` minutes the daemon re-scans
   and diffs, so a vulnerability *published overnight* for a package you
   already have surfaces within minutes, not on your next manual scan.
   Re-scan-and-diff is deliberately used instead of advisory-feed parsing:
   one OSV `querybatch` per project per cycle produces the identical result
   with zero new advisory-matching code. Daemon cycles skip NVD enrichment
   (NVD never detects, only annotates); KEV/EPSS intel stays on — it powers
   escalations — and is already cached for 24h.

## Events

Comparing each scan against the previous snapshot (`compareFindingKeys` +
per-finding metadata) yields:

| Event          | Trigger                                                        | Response |
| -------------- | -------------------------------------------------------------- | -------- |
| `baseline`     | first scan of a project this run                               | report grade; **never auto-fix** (starting a watcher must not rewrite files) |
| `new-findings` | finding keys added since the last scan                         | **auto-remediate** |
| `escalation`   | a carried-over finding's `knownExploited` flipped false → true | **auto-remediate** |
| `resolved`     | finding keys removed                                           | terminal line only |
| `scan-error`   | pipeline failure                                               | warn; notify only after 3 consecutive failures |

Escalation is why the state stores per-finding metadata, not just keys: when
CISA adds a CVE to KEV, the finding key (`package::osvId`) doesn't change —
only its urgency does.

## Auto-remediation (the default)

On `new-findings` / `escalation` the daemon:

1. builds the remediation plan (`buildRemediationPlan`),
2. rewrites `package.json` (`applyRemediationPlan` — preserves `^`/`~` style,
   transitive pins land in `overrides`, malware is deleted),
3. runs `npm install` in the project to realize the lock file
   (skipped with `--no-install`),
4. **re-scans and verifies** — the same scanner that found the problem
   confirms it is gone,
5. reports the before/after grade and the measured **MTTR** (change detected
   on disk → fix verified), and notifies.

Findings with no published fix are reported honestly as *detected, no
remediation exists yet* and are re-checked every cycle. File events caused by
the daemon's own writes are suppressed while a remediation is in flight.

`--notify-only` restores alert-only behavior (the phase-1 notification mode).

## State

`~/.fixly/daemon-state.json` (`FIXLY_HOME` overrides the directory; used by
tests). Per absolute project dir: last scan time, grade, and a
`findingKey → { severity, knownExploited }` map. Written atomically
(temp file + rename). Missing/corrupt state ⇒ treated as a first run: baseline
scan, no notifications, no fixes.

## Notifications

- **Terminal** — always; same visual language as `fixly watch`.
- **Desktop** — best-effort OS shell-outs (PowerShell toast / `osascript` /
  `notify-send`), zero added dependencies; failures degrade silently.
- **Webhook** — a stable JSON envelope (deliberately the future GitHub-Action
  contract):

```jsonc
{
  "event": "remediated",            // | "new-findings" | "escalation" | "remediation-failed"
  "project": { "dir": "...", "name": "my-api" },
  "grade": { "before": { "grade": "A", "score": 96 }, "after": { "grade": "A", "score": 96 } },
  "findings": [ { "package": "lodash", "id": "GHSA-…", "severity": "high",
                  "knownExploited": false, "epssScore": 0.42 } ],
  "remediation": { "applied": true, "verified": true, "mttrMs": 5100,
                   "changes": ["lodash: \"^4.17.20\" → \"^4.17.21\""] },
  "at": "2027-…"
}
```

## What it deliberately does not do (v1)

Feed-based OSV diffing, npm publish-stream malware watch, GitHub App / PR
creation, background service installation (run it in a terminal tab or your
OS scheduler), remote GitHub repo watching (local dirs only — remote belongs
to a hosted layer).
