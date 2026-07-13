# The foolproof guardian demo (VS Code)

The whole pitch in one minute, entirely inside the editor: a vulnerable
dependency lands → Fixly detects it in seconds → **rewrites package.json in
front of the audience** → installs → re-scans to verify → grade heals back to
A with a measured MTTR. Zero clicks after the attack.

## One-time setup (before demo day)

```powershell
pnpm install
pnpm build
```

Rehearse the full run at least once on the demo machine and network — the
first scan of a session downloads the CISA KEV catalog (cached afterwards),
so rehearsal also warms the path.

## The run

1. **Open the fixly repo in VS Code and press F5.**
   The launch config builds the extension, starts an Extension Development
   Host, and opens `examples/guardian-demo` (a clean project, lodash ^4.18.0).
2. **In the dev host:** open `package.json` in the editor (keep it visible —
   it's about to rewrite itself). Within a few seconds the status bar shows
   **`🛡 Fixly A · 100`** (the activation baseline scan).
   - Say the line: *"I will not touch the keyboard after the next command."*
3. **The attack** — open the integrated terminal (Ctrl+`) and run:
   ```
   npm install lodash@4.17.20 --no-audit --no-fund
   ```
   (The flags silence npm's own audit chatter so Fixly's response owns the
   screen. Frame it: "a developer — or an AI agent — just pulled in a
   dependency with five known CVEs.")
4. **Hands off. Watch, in order (~10–20 seconds total):**
   - the terminal panel switches itself to the **Fixly Guardian** stream:
     ```
     fixly  18:19:59  detected     5 vulnerabilities in lodash · grade F (42/100)
     fixly  18:20:00  remediating  fix package.json · npm install · verify
     fixly  18:20:04  remediated   lodash: "^4.17.20" → "^4.18.0" · grade A (100/100) · verified · MTTR 4.2s
     ```
   - status bar → **`Fixly F · 42`** on red,
   - warning toast: *"Fixly — 5 new vulnerabilities in lodash. Remediating…"*,
   - **package.json rewrites itself in the open editor** (`^4.17.20` →
     `^4.18.0`),
   - success toast: *"Fixly — remediated in N.Ns. Grade A (100/100),
     verified."*,
   - status bar back to **`Fixly A · 100`**.
5. **The receipts** — click the status bar item to open the report panel:
   the **Guardian activity feed** shows the whole story with an **MTTR
   badge**, and the hero card shows the A. Optional kill shot: press
   **Ctrl+Z in package.json** — "every fix is one undo away", then Ctrl+Shift+Z
   to redo it.

## Talking points that land

- *"Verified isn't a print statement — the same scanner that found the CVEs
  re-ran and re-derived the grade. The A is earned arithmetic."*
- *"MTTR of a few seconds, against an industry baseline — Dependabot — of a
  day."*
- *"It watches the disk, not the save button: terminal installs and AI-agent
  edits are caught the same way."* (That's why the attack comes from the
  terminal.)
- Existing findings are never auto-fixed on startup (show the
  `fixly.autoRemediate` setting if asked about consent/safety).

## Reset between runs

```powershell
git checkout -- examples/guardian-demo
cd examples/guardian-demo; npm install --no-audit --no-fund
```

Then relaunch with F5 (a fresh dev host = a fresh baseline).

## If something goes sideways (fallbacks, in order)

- **No toast after the attack?** Check the "Fixly" output channel in the dev
  host. If the network hiccuped, run **"Fixly: Scan Current Project"** from
  the command palette — the guardian diff still fires from a manual scan.
- **Auto-remediation failed (npm error)?** The panel's **⚡ Fix Everything &
  Verify** button runs the same loop — click it and narrate "one-click mode".
- **Total network outage:** fall back to the lightbulb Quick Fix on the
  squiggled dependency (works from the last completed scan) and the activity
  feed from rehearsal screenshots.

## Demo variations

- **Sick-project opening:** open `examples/demo-app` (grade F) instead — the
  baseline toast offers **Fix Everything & Verify**; one click heals the whole
  project live. Good as an encore.
- **Overnight-CVE story:** show the `fixly.advisoryIntervalMinutes` setting —
  the same loop fires on a timer with zero local changes; narrate it rather
  than simulating it.
