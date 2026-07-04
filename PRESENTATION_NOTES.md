# Fixly — Presentation Notes (Weeks 5–8)

A natural 2–3 minute speaking script covering dependency extraction, parsing,
OSV integration, and vulnerability matching, plus how I tested the demo. Pair it
with [DEMO.md](DEMO.md) for the exact commands and URLs.

---

## Opening (15 sec)

“Fixly scans the GitHub repository behind a Node.js project for known-vulnerable
npm dependencies. It reads the project’s `package.json` and `package-lock.json`,
checks every installed package — direct **and transitive** — against the OSV
vulnerability database, and cross-references CVEs with NVD. The same scanner
runs in a web app and a VS Code extension. I’ll walk through extraction,
parsing, the vulnerability APIs, and matching.”

## Week 5 — Dependency extraction (25 sec)

“First, extraction. Given a public GitHub URL, Fixly verifies the repo and branch,
then downloads `package.json` and, if present, `package-lock.json`. It supports
plain repo URLs and branch/subpath URLs for monorepos. If something’s wrong, it
returns a precise reason instead of failing silently — repo not found, private
repo, branch not found, no `package.json`, or rate-limited. A missing lockfile is
treated as a warning, not an error.”

## Week 6 — Dependency parsing (30 sec)

“Next, parsing. Fixly reads the direct `dependencies` and `devDependencies`, and
labels which is which. It prefers the **exact installed version** from the
lockfile, handling lockfile formats v1, v2, and v3 — and then it walks the
**entire lock tree**, so every transitive package is checked too, at its exact
installed version, including nested copies of the same package at different
versions. On NodeGoat that’s 36 direct dependencies but about 1,090 packages
checked in total. If there’s no lockfile, transitive discovery isn’t possible,
so Fixly falls back to direct-only with the minimum of each declared range,
clearly marked approximate. The key rule is: it never invents a version. If a
specifier like `*` or `latest` can’t be resolved, it’s skipped with a warning.”

## Week 7 — OSV API integration (30 sec)

“Then the APIs. Fixly sends each package and version to OSV’s batch endpoint,
using the npm ecosystem, and fetches the full advisory for every match. The
networking layer retries on rate limits, server errors, and network failures
with backoff, and it caps how many requests run at once so we don’t overload
OSV. Each result is normalized into one consistent shape: the advisory ID, CVE
alias, severity, CVSS score, affected ranges, and the fixed version. Then the
worst CVEs are **cross-referenced against NVD** for an independent CVSS score —
two databases agreeing is stronger evidence than one. NVD’s public API is
heavily rate-limited, so coverage is capped and the report states exactly how
many CVEs got the second opinion; an API key raises it. If neither source
provides a severity, we show ‘unknown’ — we don’t make it up.”

## Week 8 — Vulnerability matching (30 sec)

“Finally, matching. OSV does the authoritative match — we send a concrete version,
and it only returns advisories whose affected ranges include that version, so it’s
range-based, not just a name match. On top of that, Fixly independently
re-verifies, with its own semver logic, that the installed version really falls
inside the advisory’s affected range, and it displays that range. If it can’t
verify a case locally, it marks it as limited confidence instead of overstating.
Findings are sorted by severity, then package name.”

## How I tested the demo (30 sec)

“For testing, I work in three layers. First, terminal checks: `pnpm test` runs 85
unit tests covering parsing, transitive discovery, OSV normalization, NVD
enrichment, matching, and the history diff; and `pnpm validate` runs the real
scanner against live repos — a vulnerable one, a clean one, and every error
case. Then I build, lint, and typecheck the whole workspace. Second, the
browser demo: I use a bundled vulnerable fixture so the demo doesn’t depend on
GitHub’s rate limit — it returns 50-plus real findings, including transitive
ones, and re-scanning shows the new/resolved delta from the browser’s scan
history. Third, I scan a real public repo, OWASP NodeGoat — about 1,090
packages and 267 findings — to prove the full extraction flow end-to-end, and I
show that bad input gives a clean error, not a crash.”

## Closing (10 sec)

“So Fixly takes a repository, safely extracts and parses its full dependency
tree, checks it against OSV, cross-references NVD, tracks changes across scans,
and reports real vulnerabilities with severity, CVSS, and fix versions —
honestly, without inventing data. In the editor, it flags vulnerable
dependencies right on package.json and rescans on save. Happy to take
questions.”

---

## Honest scope (if asked)

- npm only (yarn/pnpm lock files aren’t parsed — those scan as direct-only).
- Transitive analysis requires `package-lock.json`; without it, direct-only + warning.
- Public GitHub repos only; unauthenticated, so it can be rate-limited — that’s why
  the bundled fixture is the safest demo path.
- OSV detects; NVD cross-checks (best-effort under its public rate limit — the
  report always states coverage; a free API key raises it).
- Scan history is per-browser (localStorage) — no accounts or server database.
- No lockfile → approximate (range-minimum), and findings are tagged as such.
- Severity/CVSS shown only when OSV/NVD provide them.
