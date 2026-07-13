# Fixly demo script — real-time remediation (VS Code)

~6 minutes. Three attacks, escalating stakes. Spoken lines in quotes;
commands in blocks; [brackets] = what happens on screen.

## Pre-flight (before anyone is watching)

```powershell
cd C:\Users\Diomio\Desktop\fixly
git checkout -- examples/guardian-demo
cd examples\guardian-demo; npm install --no-audit --no-fund; cd ..\..
```

F5 → test window opens → open `package.json` → wait for **Fixly A · 100**
in the status bar. Font size up. Terminal open (Ctrl+`).

---

## Opening (30s)

> "Every npm project ships with hundreds of dependencies you didn't write.
> When one of them turns out to be vulnerable, the industry's answer is a
> daily bot that opens a pull request you'll read tomorrow. Fixly's answer
> is different: detect it in seconds, fix it automatically, and prove the
> fix worked. This is a real-time remediation engine, and it lives where
> developers actually work — the editor."

Point at the status bar:

> "This project is clean — Fixly grades it A, 100 out of 100. The guardian
> is watching the dependency files on disk. I'm going to attack this
> project three times, each worse than the last. **After each attack
> command, I won't touch the keyboard.**"

---

## Act 1 — Detection to remediation in seconds (90s)

```powershell
npm install lodash@4.17.20 --no-audit --no-fund
```

> "A developer — or an AI coding agent, which is who's writing half the
> code in 2026 — just installed a lodash version with five known CVEs."

Hands visibly off. [Guardian terminal takes over: detected → remediating →
remediated; status bar A→F→A; package.json rewrites itself; green toast.]

> "Watch the sequence: Fixly detected five vulnerabilities within seconds
> of the file changing on disk. The grade crashed to an F. Then it rewrote
> package.json itself — watch the version change in the open editor — ran
> the install, and re-scanned. That last step matters: **'verified' means
> the same scanner that found the problem confirms it's gone.** Time to
> remediate: under five seconds. Dependabot's baseline is a day."

Proof (type these):

```powershell
git diff package.json
npm audit
```

> "The diff shows a machine wrote this change, not me. And npm's own
> auditor — a tool Fixly doesn't control — independently says zero
> vulnerabilities."

---

## Act 2 — Dependencies of dependencies (90s)

```powershell
npm install express@4.17.1 --no-audit --no-fund
```

> "Harder problem. Express itself is one package — but it pulls in a tree
> of thirty more. The vulnerabilities are in packages I never chose and
> can't upgrade directly. Most tools stop here and tell you to wait for
> express to update."

[Guardian fires; findings table shows `transitive` tags; package.json
gains an `overrides` block.]

> "Fixly walked the lock-file tree, found the vulnerable packages *inside*
> express, and pinned each one to its fixed version using npm's overrides
> mechanism — surgical fixes deep in the dependency tree, no waiting for
> upstream. Verified the same way: re-scan, grade restored."

```powershell
git diff package.json
```

> "There's the overrides block — written, installed, and verified without
> a human decision."

---

## Act 3 — Exploited in the wild (60s)

```powershell
npm install mongo-express@0.53.0 --no-audit --no-fund
```

> "Last one. This package's vulnerability isn't theoretical — it's in
> CISA's Known Exploited Vulnerabilities catalog. The U.S. government
> confirms attackers are using it right now."

[Report panel: red **KEV** tag; grade takes the +25 KEV penalty; guardian
remediates.]

> "Fixly cross-references every finding against the KEV catalog and EPSS
> exploit-prediction scores, and weighs the grade accordingly — a
> vulnerability being actively exploited is not the same as a theoretical
> one. And by the time I finished that sentence, it was already fixed and
> verified."

---

## Close (45s)

Click the status bar → report panel. Point at the Guardian activity feed.

> "The full session, timestamped: three attacks, three automatic
> remediations, each verified, each with a measured time-to-remediate in
> seconds. Under the hood this is one engine — an OSV-backed scanner, a
> deterministic A-to-F grade, and a remediation planner whose forecast is
> real arithmetic — shipped across five surfaces: this extension, a CLI
> daemon, a web scanner, and an MCP server so AI agents can use it too.
> Real-time remediation isn't a report that asks you to act. It's a system
> that acts, and then proves it."

(Optional mic drop: Ctrl+Z in package.json — "and every fix is one undo
away." Ctrl+Shift+Z to restore.)

---

## Q&A parries

- **"Is it actually fixing or just printing?"** → `git diff`, `npm ls`,
  `npm audit` — machine-written diff, real installed version, independent
  auditor agrees.
- **"What does 'verified' mean exactly?"** → The post-fix re-scan queries
  OSV again and confirms every finding the plan promised to fix is gone.
  Same evidence standard as Snyk/Dependabot.
- **"What if there's no fix released?"** → Fixly fixes what it can and
  reports the rest as *unfixable* — honesty is a design rule. (`ip@2.0.0`
  demonstrates it if they want to see.)
- **"What if I don't want auto-fix?"** → `fixly.autoRemediate: false`
  turns it into a one-click prompt; baselines are never auto-fixed.
- **"Why not just npm audit fix?"** → npm audit fix doesn't verify, can't
  do KEV/EPSS prioritization, has no grade, and famously breaks builds
  with --force. Fixly plans, applies, installs, and re-verifies as one
  transaction — and shows you the forecast before and the receipt after.

## Recovery moves (if something stalls)

1. Ctrl+Shift+P → **Fixly: Scan Current Project** (guardian resumes).
2. Report panel → **Fix Everything & Verify** (narrate as one-click mode).
3. Reset hard: `git checkout -- package.json package-lock.json` +
   `npm install --no-audit --no-fund`, relaunch F5.
