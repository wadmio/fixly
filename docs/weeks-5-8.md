# Weeks 5–8 — Dependency Extraction → Vulnerability Matching

This document maps the Week 5–8 milestones to the code, tests, and documentation
that satisfy them, and explains the logic the rubric asks us to write down
(parser, API flow, matching). Everything here is backed by code in
[`packages/core`](../packages/core) and tests that run with `pnpm test`.

Pipeline at a glance:

```
GitHub repo URL ──▶ fetchProject ──▶ parseDependencies ──▶ queryOsvBatch ──▶ normalize ──▶ sortBySeverity
(or local files) ──▶ scanProjectFiles ───────────────────────────────────────────────────▶ ScanResult
      Week 5                Week 6              Week 7            Week 7/8        Week 8
```

---

## Week 5 — Dependency Extraction

**Goal: extract `package.json` and `package-lock.json` from public GitHub repos.**

| Deliverable | Where | Status |
|---|---|---|
| Retrieve dependency files from public repos | [`github.ts`](../packages/core/src/github.ts) `fetchProject()` | ✅ |
| Support normal + branch/subpath URLs | [`github-url.ts`](../packages/core/src/github-url.ts) `parseGitHubUrl()` | ✅ |
| Handle invalid / private / missing / unsupported repos | structured `FetchErrorCode` (below) | ✅ |
| Explain missing `package-lock.json` instead of failing silently | warning in [`parse-packages.ts`](../packages/core/src/parse-packages.ts) | ✅ |
| Tests on sample repos / fixtures | [`github-fetch.test.ts`](../packages/core/tests/github-fetch.test.ts), [`validation-notes.md`](../validation-notes.md) | ✅ |

### Supported files, limits, and unsupported cases

**Supported input**

- A public `github.com` repo URL: `https://github.com/owner/repo`.
- Branch + subpath URLs: `https://github.com/owner/repo/tree/<branch>/<subpath>`
  (a monorepo package folder is fetched from that subfolder).
- Files read: `package.json` (**required**) and `package-lock.json` (**optional**).

**How extraction works.** `fetchProject` verifies the repo (and the branch, if the
URL names one) up front via the GitHub REST API, resolves the default branch when
none is given, then downloads the two files from the GitHub Contents API and
base64-decodes them. It returns a discriminated result — on success the parsed
files plus `branch`, `filesFound`, `filesMissing`; on failure a precise code:

| Code | Cause |
|---|---|
| `repo_not_found` | Repo 404s (may not exist, or is private). |
| `private_repo` | 403/401 without a rate-limit message. |
| `branch_not_found` | A URL-specified branch does not exist. |
| `no_package_json` | No `package.json` on that branch/subpath, or it isn't valid JSON. |
| `rate_limited` | GitHub rate limit hit (403/429 + rate-limit message). |
| `github_error` | Any other unexpected GitHub status. |

**Limits / unsupported (by design)**

- npm only; public repos only; unauthenticated (optional `GITHUB_TOKEN` raises the limit).
- A **missing `package-lock.json` is not an error** — it's recorded in
  `filesMissing` and produces a warning (versions become approximate; see Week 6).
- Not supported: private repos, non-GitHub hosts (→ `invalid_url`), yarn/pnpm lockfiles,
  and dependency files in non-standard locations other than a given subpath.

---

## Week 6 — Dependency Parsing

**Goal: parse package names and installed versions from the manifest files.**

| Deliverable | Where | Status |
|---|---|---|
| Parse names + installed versions | [`parse-packages.ts`](../packages/core/src/parse-packages.ts) `parseDependencies()` | ✅ |
| Prefer exact lockfile versions | `resolveCheckVersion()` (lock version first) | ✅ |
| Support lock v1, v2, v3 | `extractLockVersions()` | ✅ |
| Include deps + devDeps, labelled | `DependencyEntry.dependencyType` | ✅ |
| Avoid false confidence on ranges without a lockfile | range-minimum + warning + per-finding `(≈ approx)` tag | ✅ |
| Validation tests | [`parse-packages.test.ts`](../packages/core/tests/parse-packages.test.ts) | ✅ |

### Parser logic

1. **Collect direct dependencies.** Only top-level `dependencies` and
   `devDependencies` from `package.json` are read (no transitive resolution). Each
   becomes a `DependencyEntry { name, requestedVersion, installedVersion,
   dependencyType, sourceFile }`. If a package appears in both maps, the
   `dependencies` entry wins (deduped by name).

2. **Resolve the installed version from the lockfile.** `extractLockVersions`
   handles all three lockfile formats:
   - **v1** — a flat `dependencies` map keyed by package name.
   - **v2 / v3** — a `packages` map keyed by install path; we take only
     top-level `node_modules/<name>` entries and **skip nested**
     `.../node_modules/...` paths (those are transitive).

3. **Decide the version to check** (`resolveCheckVersion`):
   - the exact `installedVersion` from the lockfile when present, else
   - the **minimum** of the declared range (`cleanVersion` strips `^ ~ >= < v`),
     which is approximate, else
   - `null` — the specifier can't be resolved to a concrete version.

4. **Never invent versions.** Unresolvable specifiers (`*`, `latest`/dist-tags,
   `npm:` aliases, git/file URLs) resolve to `null`, are **skipped**, and are
   reported in a warning. A missing lockfile also produces a warning, and every
   range-minimum finding is tagged `(≈ approx)` in the UI — so a `^1.2.3` with no
   lockfile never masquerades as a confirmed installed version.

---

## Week 7 — API Integration (OSV)

**Goal: connect parsed dependencies to OSV and normalize the data.**

| Deliverable | Where | Status |
|---|---|---|
| OSV request/response flow (ecosystem `npm`) | [`osv.ts`](../packages/core/src/osv.ts) `queryOsvBatch()` | ✅ |
| Retry/backoff for 429 / 5xx / network | [`http.ts`](../packages/core/src/http.ts) `fetchWithRetry()` | ✅ |
| Rate-limit-friendly batching + concurrency cap | `querybatch` chunks of 999; `mapWithConcurrency` cap 8 | ✅ |
| Normalize to a consistent internal shape | [`normalize.ts`](../packages/core/src/normalize.ts) → `ScanVulnerability` | ✅ |
| Don't invent missing severity/CVSS | resolves to `"unknown"` / `null` | ✅ |
| NVD | **not implemented** by design — see [vulnerability-sources.md](vulnerability-sources.md) | ➖ |

### OSV request/response flow

**Step 1 — `POST https://api.osv.dev/v1/querybatch`** with one entry per package:

```jsonc
{ "queries": [
  { "package": { "name": "lodash", "ecosystem": "npm" }, "version": "4.17.4" }
] }
```

OSV returns only the advisory **ids** whose affected ranges include that version
(version-filtered, not name-only). Queries are sent in chunks of 999.

**Step 2 — `GET https://api.osv.dev/v1/vulns/{id}`** for each unique id, fetched
with a concurrency cap of 8. The full record carries `aliases`, `severity`
(CVSS vectors), `affected[].ranges` (events), `references`, and `summary`.

**Reliability.** Both GitHub and OSV calls go through `fetchWithRetry`:
exponential backoff + jitter, honoring `Retry-After`, retrying network errors /
429 / 5xx and **not** retrying definitive 404/403.

### Normalized shape (`ScanVulnerability`)

| Field | Source | Missing → |
|---|---|---|
| `osvId` | record `id` | — |
| `cveId` | first `CVE-…` alias | `null` |
| `package`, `installedVersion` | the checked dependency | — |
| `affectedRanges` | `affected[].ranges` events, rendered (`<4.17.12`) | `[]` |
| `severity` | `database_specific.severity` → CVSS band → per-affected → | `"unknown"` |
| `cvssScore` / `cvssVector` | CVSS v3 vector (score computed locally) | `null` |
| `fixedVersion` | first `fixed` event | `null` |
| `versionInRange` | local re-check (Week 8) | `null` (not verifiable) |
| `versionSource` | `"lockfile"` or `"range-minimum"` | — |
| `references` | `references[].url` | `[]` |

### CVE / CVSS / severity / affected-version fields (research notes)

- **CVE** is an alias on the OSV record; OSV's own id is usually a `GHSA-…`. We
  surface both. A record may have **no** CVE — then `cveId` is `null`.
- **CVSS** comes as a vector string (e.g. `CVSS:3.1/AV:N/...`). We compute the
  v3.1 **base score** locally from the vector (FIRST.org formula in
  `cvssV3BaseScore`) rather than trusting a possibly-absent numeric field.
- **Severity** is resolved by priority: GitHub-Advisory `database_specific.severity`
  → CVSS-derived band → per-`affected` severity → `unknown`. We never fabricate it.
- **Affected versions** live in `affected[].ranges[].events` as ordered
  `introduced` / `fixed` / `last_affected` markers (plus an optional explicit
  `versions` list). These drive both the displayed range and Week 8 matching.

---

## Week 8 — Vulnerability Matching

**Goal: match installed versions against known vulnerable versions, reduce false
positives, mark limited confidence, and validate accuracy.**

| Deliverable | Where | Status |
|---|---|---|
| Match installed version against vulnerable ranges | OSV `querybatch` (authoritative) + local re-check | ✅ |
| Correct semver logic, range/event based (not name-only) | [`matching.ts`](../packages/core/src/matching.ts) | ✅ |
| Reduce false positives | exact-version-first, skip-unresolvable, range/event check | ✅ |
| Mark limited-confidence cases | `versionInRange: null`, `versionSource: "range-minimum"` | ✅ |
| Sort by severity, then package name | [`scan.ts`](../packages/core/src/scan.ts) `sortBySeverity()` | ✅ |
| Validate with known vulnerable + non-vulnerable versions | [`matching.test.ts`](../packages/core/tests/matching.test.ts) | ✅ |

### How matching works (and why it's accurate)

The authoritative match is done by **OSV**: we send each package's concrete
version to `querybatch`, and OSV returns only advisories whose affected ranges
include that version. This is range/event-based by construction — a package name
alone never produces a finding.

On top of that, [`matching.ts`](../packages/core/src/matching.ts) **independently
re-evaluates** each returned advisory's `introduced` / `fixed` / `last_affected`
events with a dependency-free semver comparator, and records the result on every
finding as `versionInRange`:

- `true` — local check confirms the installed version is in the affected range,
- `false` — evaluable but out of range (does not occur for OSV hits in practice;
  a guard against disagreement),
- `null` — **not locally evaluable** (non-semver range or unparseable version) →
  shown as limited confidence rather than overstated.

This re-check is a **transparency layer**: it never drops an OSV finding (OSV is
the authority), it only annotates and lets the UI display the matched range.

### Reducing false results

- **Exact version first.** With a lockfile, the precise installed version is
  checked — no range guessing.
- **Never guess.** Unresolvable specifiers are skipped + warned, not invented.
- **Range/event matching**, not name matching — both at OSV and in our re-check.
- **Approximate clearly flagged.** No lockfile → range-minimum is used, the
  finding is `versionSource: "range-minimum"`, and the UI tags it `(≈ approx)`.
- **Direct deps only** keeps scope honest (no inferred transitive matches).

### Validation

- Unit tests in [`matching.test.ts`](../packages/core/tests/matching.test.ts) assert
  in-range **true** (e.g. `lodash 4.17.4` vs `<4.17.12`), at/after-fix **false**
  (`4.17.12`, `4.17.21`), `last_affected` inclusivity, explicit version lists,
  and `null` for non-evaluable cases.
- Live evidence in [validation-notes.md](../validation-notes.md): `OWASP/NodeGoat`
  reproduces its expected finding counts; the bundled fixture
  (`?fixture=vulnerable-demo`) returns 50+ real OSV findings, **all** confirmed
  in-range by the local matcher.

---

## Run it

```bash
pnpm test          # 60 unit tests (extraction, parsing, OSV normalize, matching, sort, reliability)
pnpm validate      # live scans vs sample repos → validation-notes.md
pnpm dev           # web app; see ../DEMO.md for the click-path
```
