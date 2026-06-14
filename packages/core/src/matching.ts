import type { OsvVuln } from "./osv";

// ---------------------------------------------------------------------------
// Version matching — dependency-free semver comparison + OSV range evaluation.
//
// How matching actually works in Fixly: we send a single concrete version per
// package to OSV's /querybatch, and OSV returns only the advisories whose
// affected ranges include that version. OSV is therefore the authority on
// "is this version vulnerable" — it matches on ranges/events, not just names.
//
// This module re-checks that match locally so we can:
//   1. display the affected range next to the installed version, and
//   2. mark a finding's confidence (confirmed in range / not locally verifiable).
// It is a transparency layer: we never use it to drop an OSV finding, only to
// annotate it. When a range can't be evaluated locally we return `null`
// ("limited confidence") rather than guessing.
// ---------------------------------------------------------------------------

interface ParsedVersion {
  /** Numeric release identifiers: [major, minor, patch, ...]. */
  parts: number[];
  /** The pre-release tag (e.g. "beta.1") or null for a normal release. */
  prerelease: string | null;
}

/**
 * Parse a semver-ish string ("1.2.3", "v1.2", "1.2.3-beta.1", "1.2.3+build")
 * into numeric release parts plus an optional pre-release tag. Returns null if
 * the value is not a numeric-dotted version, so callers can treat it as
 * "not locally evaluable" instead of comparing garbage.
 */
export function parseVersion(raw: string): ParsedVersion | null {
  if (!raw) return null;
  let v = raw.trim().replace(/^v/i, "");
  v = v.split("+")[0]; // drop build metadata (ignored for precedence)
  const dash = v.indexOf("-");
  const core = dash === -1 ? v : v.slice(0, dash);
  const prerelease = dash === -1 ? null : v.slice(dash + 1) || null;
  const parts = core.split(".").map((n) => Number(n));
  if (parts.length === 0 || parts.some((n) => !Number.isInteger(n) || n < 0)) {
    return null;
  }
  return { parts, prerelease };
}

function comparePrerelease(a: string, b: string): number {
  const as = a.split(".");
  const bs = b.split(".");
  const len = Math.max(as.length, bs.length);
  for (let i = 0; i < len; i++) {
    // A larger set of pre-release fields has higher precedence when all
    // preceding identifiers are equal (1.0.0-alpha < 1.0.0-alpha.1).
    if (as[i] === undefined) return -1;
    if (bs[i] === undefined) return 1;
    const an = /^\d+$/.test(as[i]);
    const bn = /^\d+$/.test(bs[i]);
    if (an && bn) {
      const d = Number(as[i]) - Number(bs[i]);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (an) {
      return -1; // numeric identifiers have lower precedence than alphanumeric
    } else if (bn) {
      return 1;
    } else if (as[i] !== bs[i]) {
      return as[i] < bs[i] ? -1 : 1;
    }
  }
  return 0;
}

function compareParsed(a: ParsedVersion, b: ParsedVersion): number {
  const len = Math.max(a.parts.length, b.parts.length);
  for (let i = 0; i < len; i++) {
    const ai = a.parts[i] ?? 0;
    const bi = b.parts[i] ?? 0;
    if (ai !== bi) return ai < bi ? -1 : 1;
  }
  // Equal release numbers: a pre-release is lower than the normal release.
  if (a.prerelease === null && b.prerelease === null) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return comparePrerelease(a.prerelease, b.prerelease);
}

/**
 * Compare two version strings. Returns -1, 0, or 1, or null if either side is
 * not a parseable numeric semver.
 */
export function compareSemver(a: string, b: string): number | null {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return null;
  return compareParsed(pa, pb);
}

function affectedEntriesFor(vuln: OsvVuln, packageName?: string) {
  return (vuln.affected ?? []).filter(
    (a) => !packageName || !a.package?.name || a.package.name === packageName
  );
}

// Only semver-ordered range types can be compared with parsed versions.
function isSemverRange(type: string): boolean {
  return type === "SEMVER" || type === "ECOSYSTEM";
}

/**
 * Decide whether `version` falls inside any of an advisory's affected ranges,
 * evaluating OSV's ordered introduced/fixed/last_affected events. Also honours
 * an explicit `affected.versions` list.
 *
 * Returns:
 *   - true  — the version is within an affected range,
 *   - false — ranges were evaluable and the version is outside all of them,
 *   - null  — nothing could be evaluated locally (e.g. non-semver ranges or an
 *             unparseable version) → treat as limited confidence.
 */
export function isVersionInOsvRanges(
  version: string,
  vuln: OsvVuln,
  packageName?: string
): boolean | null {
  const target = parseVersion(version);
  if (!target) return null;

  let evaluable = false;

  for (const affected of affectedEntriesFor(vuln, packageName)) {
    if (Array.isArray(affected.versions) && affected.versions.length > 0) {
      evaluable = true;
      if (affected.versions.includes(version)) return true;
    }

    for (const range of affected.ranges ?? []) {
      if (!isSemverRange(range.type)) continue;
      let introduced: ParsedVersion | null = null;

      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) {
          // "0" means "from the beginning of time".
          introduced =
            event.introduced === "0"
              ? { parts: [0], prerelease: null }
              : parseVersion(event.introduced) ?? { parts: [0], prerelease: null };
        } else if (event.fixed !== undefined) {
          const fixed = parseVersion(event.fixed);
          if (introduced && fixed) {
            evaluable = true;
            if (compareParsed(target, introduced) >= 0 && compareParsed(target, fixed) < 0) {
              return true;
            }
          }
          introduced = null;
        } else if (event.last_affected !== undefined) {
          const last = parseVersion(event.last_affected);
          if (introduced && last) {
            evaluable = true;
            if (compareParsed(target, introduced) >= 0 && compareParsed(target, last) <= 0) {
              return true;
            }
          }
          introduced = null;
        }
      }

      // Open-ended range: "introduced" with no closing event → affected from
      // that version onward.
      if (introduced) {
        evaluable = true;
        if (compareParsed(target, introduced) >= 0) return true;
      }
    }
  }

  return evaluable ? false : null;
}

function formatBound(introduced: string | null, op: "<" | "<=" | null, bound: string | null): string {
  const lo = introduced && introduced !== "0" ? `>=${introduced}` : "";
  const hi = op && bound ? `${op}${bound}` : "";
  return [lo, hi].filter(Boolean).join(" ") || "all versions";
}

/**
 * Render an advisory's affected ranges as human-readable strings, e.g.
 * `">=0 <4.17.12"`, `"<=2.6.6"`, or `">=1.0.0"`. Used for display only.
 */
export function formatAffectedRanges(vuln: OsvVuln, packageName?: string): string[] {
  const out: string[] = [];

  for (const affected of affectedEntriesFor(vuln, packageName)) {
    for (const range of affected.ranges ?? []) {
      if (!isSemverRange(range.type)) continue;
      let introduced: string | null = null;
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) {
          introduced = event.introduced;
        } else if (event.fixed !== undefined) {
          out.push(formatBound(introduced, "<", event.fixed));
          introduced = null;
        } else if (event.last_affected !== undefined) {
          out.push(formatBound(introduced, "<=", event.last_affected));
          introduced = null;
        }
      }
      if (introduced !== null) out.push(formatBound(introduced, null, null));
    }
  }

  return [...new Set(out)];
}
