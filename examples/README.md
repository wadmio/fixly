# Demo projects

Manifest-only demo projects for the fixly CLI — **plain JSON, nothing is
installed here, and nothing should be**. They exist so `fixly vibecheck` /
`scan` / the MCP `scan_project` tool have a reproducible target from a clean
checkout (not part of the pnpm workspace).

| Project | What it demos | Expected result |
|---|---|---|
| `demo-app/` | Real packages pinned to old releases with real OSV advisories, incl. lock-only transitive packages (`request`, `tough-cookie`) and a **CISA KEV** finding (`mongo-express@0.53.0`, CVE-2019-10758 — exploited in the wild). | **F** — ~40 findings, criticals, the ⚡ KEV badge, top fixes with copy-paste commands. |
| `clean-app/` | A healthy project. | **A (100/100)** — "Ship it." |

```bash
pnpm build   # once, from the repo root
node apps/cli/dist/cli.js vibecheck examples/demo-app
node apps/cli/dist/cli.js vibecheck examples/clean-app
node apps/cli/dist/cli.js scan examples/demo-app --sarif > fixly.sarif
```

⚠ **Do not run `npm install` inside `demo-app/`** — the whole point is that
these dependencies are vulnerable. The known-**malicious** package demo
(`lodahs`) is deliberately *not* on disk here; it lives in the web app's
in-memory fixture (`/dashboard/results?fixture=vulnerable-demo`) and in
`fixly check lodahs` / `fixly guard`, which need no files at all.

Findings counts drift over time — OSV is live and new advisories land on old
versions. The grade letters are stable.
