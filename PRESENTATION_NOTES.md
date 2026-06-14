# Fixly — Presentation Notes (Weeks 5–8)

A natural 2–3 minute speaking script covering dependency extraction, parsing,
OSV integration, and vulnerability matching, plus how I tested the demo. Pair it
with [DEMO.md](DEMO.md) for the exact commands and URLs.

---

## Opening (15 sec)

“Fixly scans the GitHub repository behind a Node.js project for known-vulnerable
npm dependencies. It reads the project’s `package.json` and `package-lock.json`,
checks each dependency against the OSV vulnerability database, and shows clear
results. The same scanner runs in a web app and a VS Code extension. I’ll walk
through Weeks 5 to 8 — extraction, parsing, the OSV API, and matching.”

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
lockfile, and it handles lockfile formats v1, v2, and v3 — taking only top-level
packages, not nested transitive ones. If there’s no lockfile, it falls back to
the minimum version of the declared range and clearly marks that result as
approximate. The key rule is: it never invents a version. If a specifier like
`*` or `latest` can’t be resolved, it’s skipped with a warning.”

## Week 7 — OSV API integration (30 sec)

“Then the API. Fixly sends each package and version to OSV’s batch endpoint, using
the npm ecosystem, and fetches the full advisory for every match. The networking
layer retries on rate limits, server errors, and network failures with backoff,
and it caps how many requests run at once so we don’t overload OSV. Each result is
normalized into one consistent shape: the advisory ID, CVE alias, severity, CVSS
score, affected ranges, and the fixed version. If OSV doesn’t provide a severity
or CVSS, we show ‘unknown’ — we don’t make it up. NVD is documented as future
work; right now OSV is the source.”

## Week 8 — Vulnerability matching (30 sec)

“Finally, matching. OSV does the authoritative match — we send a concrete version,
and it only returns advisories whose affected ranges include that version, so it’s
range-based, not just a name match. On top of that, Fixly independently
re-verifies, with its own semver logic, that the installed version really falls
inside the advisory’s affected range, and it displays that range. If it can’t
verify a case locally, it marks it as limited confidence instead of overstating.
Findings are sorted by severity, then package name.”

## How I tested the demo (30 sec)

“For testing, I work in three layers. First, terminal checks: `pnpm test` runs 60
unit tests covering parsing, OSV normalization, and the matching logic; and
`pnpm validate` runs the real scanner against live repos — a vulnerable one, a
clean one, and every error case. Then I build, lint, and typecheck the whole
workspace. Second, the browser demo: I use a bundled vulnerable fixture so the
demo doesn’t depend on GitHub’s rate limit — it returns 50-plus real findings.
Third, I scan a real public repo, OWASP NodeGoat, to prove the full extraction
flow works end-to-end, and I show that bad input gives a clean error, not a
crash.”

## Closing (10 sec)

“So Fixly takes a repository, safely extracts and parses its dependencies, checks
them against OSV, and reports real vulnerabilities with severity, CVSS, and fix
versions — honestly, without inventing data. Happy to take questions.”

---

## Honest scope (if asked)

- npm only; direct dependencies only (no transitive analysis).
- Public GitHub repos only; unauthenticated, so it can be rate-limited — that’s why
  the bundled fixture is the safest demo path.
- OSV implemented; NVD is future work.
- No lockfile → approximate (range-minimum), and findings are tagged as such.
- Severity/CVSS shown only when OSV provides them.
