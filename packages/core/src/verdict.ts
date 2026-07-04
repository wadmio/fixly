// The verdict engine — Fixly's one-question API: "should this package go into
// a project right now?" Answered SAFE / CAUTION / BLOCK with plain-English
// reasons, built for surfaces where a wall of CVE JSON is useless: an AI
// coding agent mid-generation (MCP), an install shim, a CLI one-liner.
//
// Design rules:
//   - Verdicts are transparent — every escalation appends a human-readable
//     reason; nothing is a black box.
//   - Signals degrade independently: if the registry or an intel feed is
//     unreachable, the verdict is computed from what remains and says so in
//     `warnings` — "couldn't check" is never silently treated as "safe".
//   - BLOCK is reserved for evidence (malware record, nonexistent name,
//     exploited-in-the-wild vuln), CAUTION for suspicion. False BLOCKs burn
//     trust faster than false CAUTIONs.

import { queryOsvPackage, type OsvVuln } from "./osv";
import { normalizeOsvResults } from "./normalize";
import { enrichWithIntel } from "./intel";
import { fetchRegistryInfo, fetchLatestVersion, fetchDistTagVersion, type RegistryInfo } from "./registry";
import { findTyposquatTarget } from "./typosquat";
import { isPopularPackage } from "./popular-packages";
import { scoreNameRisk } from "./name-model";
import type { ScanVulnerability, Severity } from "./types";

// "unknown" = we could not perform the checks that clear a package (registry
// existence and/or OSV were unreachable). It is NOT "safe" — the engine never
// fails open. Callers should treat it as "not yet cleared".
export type VerdictLevel = "safe" | "caution" | "block" | "unknown";

export interface PackageSignals {
  exists: boolean | null;
  versionExists: boolean | null;
  popular: boolean;
  ageDays: number | null;
  lastPublishDays: number | null;
  weeklyDownloads: number | null;
  deprecated: boolean;
  hasInstallScripts: boolean | null;
  maintainers: number | null;
  typosquatOf: string | null;
  /** ML name-risk score (0–1) from the ONNX model, or null when unavailable. */
  nameRiskScore: number | null;
  /** True when the ML model flagged the name above its tuned threshold. */
  nameRiskFlagged: boolean;
  maliciousIds: string[];
  vulnerabilityCounts: Record<Severity, number>;
  knownExploitedCves: string[];
  /** Highest EPSS score among the findings' CVEs (0–1). */
  maxEpss: number | null;
}

export interface PackageVerdict {
  package: string;
  /** The version the caller asked about (null = name-only check). */
  version: string | null;
  /** The version actually evaluated (the latest, for name-only checks). */
  evaluatedVersion: string | null;
  verdict: VerdictLevel;
  /** Human-readable reasons, worst first. Empty for a clean SAFE. */
  reasons: string[];
  /** One-line human summary of the verdict (agent/CLI friendly). */
  summary: string;
  signals: PackageSignals;
  /** Findings behind the verdict (empty when none or not evaluable). */
  vulnerabilities: ScanVulnerability[];
  /** Signal sources that could not be checked ("couldn't check" ≠ "safe"). */
  warnings: string[];
}

const NEW_PACKAGE_DAYS = 30;
const LOW_DOWNLOADS_PER_WEEK = 500;
const HIGH_EPSS = 0.1; // ≥10% predicted 30-day exploitation probability

function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}

/** An exact semver (1.2.3 / 1.2.3-rc.1) — not a dist-tag or range. */
function isExactVersion(v: string): boolean {
  return /^\d+\.\d+\.\d+(-[\w.]+)?$/.test(v);
}

export interface CheckPackageOptions {
  /** Skip the OSV vulnerability lookup (offline name-only checks). */
  osv?: boolean;
  /** Skip KEV/EPSS enrichment. */
  intel?: boolean;
}

/**
 * Full trust check for one package (optionally at one version): registry
 * profile, typosquat analysis, OSV advisories (incl. `MAL-` malware records),
 * and KEV/EPSS exploit intelligence, synthesized into a single verdict.
 */
export async function checkPackage(
  name: string,
  version?: string | null,
  options: CheckPackageOptions = {}
): Promise<PackageVerdict> {
  const warnings: string[] = [];
  const popular = isPopularPackage(name);

  // --- Resolve a dist-tag/range (e.g. "next", "^1.2.0") to the concrete
  // version an install would actually fetch, so the verdict evaluates the right
  // one instead of silently falling back to `latest`. Exact versions pass
  // through untouched; an unresolvable tag/range falls back to latest below.
  let requestedVersion: string | null = version ?? null;
  if (requestedVersion && !isExactVersion(requestedVersion)) {
    try {
      const resolved = await fetchDistTagVersion(name, requestedVersion);
      if (resolved) {
        warnings.push(`"${requestedVersion}" resolves to ${resolved} — evaluating that version.`);
        requestedVersion = resolved;
      } else {
        requestedVersion = null; // unknown tag/range → evaluate latest instead
      }
    } catch {
      requestedVersion = null;
    }
  }

  // --- Registry profile (skipped for curated-popular packages: their
  // packuments are huge and their existence isn't in question).
  let registry: RegistryInfo | null = null;
  if (!popular) {
    try {
      registry = await fetchRegistryInfo(name, requestedVersion);
    } catch {
      warnings.push("npm registry was unreachable — existence/age/download signals are missing.");
    }
  }

  // --- Typosquat / hallucination adjacency (pure string analysis) + the
  // optional ML name-risk model (trained in ml/, runs via ONNX when present).
  const typosquat = popular ? null : findTyposquatTarget(name);
  const nameRisk = popular ? null : await scoreNameRisk(name);

  // --- The version to evaluate. A name-only check evaluates what an install
  // would fetch TODAY (the latest version) — never the package's entire
  // historical advisory record, which would flag long-fixed CVEs.
  let effectiveVersion: string | null = requestedVersion ?? registry?.latestVersion ?? null;
  if (!effectiveVersion && registry?.exists !== false) {
    try {
      effectiveVersion = await fetchLatestVersion(name);
    } catch {
      // handled below: no version → OSV check is skipped with a warning
    }
  }

  // --- OSV advisories (vulnerabilities + MAL- malware records).
  // Track whether an ENABLED OSV check actually completed: if OSV was requested
  // but couldn't run, there's no malware/vuln evidence, so "safe" would be a
  // fail-open guess (see the unknown-verdict override below). A caller that
  // opts out of OSV (options.osv === false) is treated as "not required".
  let vulnerabilities: ScanVulnerability[] = [];
  const osvEnabled = options.osv ?? true;
  let osvChecked = !osvEnabled;
  if (osvEnabled && registry?.exists !== false) {
    if (effectiveVersion) {
      try {
        const osvVulns: OsvVuln[] = await queryOsvPackage(name, effectiveVersion);
        vulnerabilities = normalizeOsvResults(name, effectiveVersion, osvVulns);
        osvChecked = true;
      } catch {
        warnings.push("OSV was unreachable — vulnerability/malware records could not be checked.");
      }
    } else {
      warnings.push(
        "Could not determine a version to evaluate — vulnerability records were not checked."
      );
    }
  } else if (registry?.exists === false) {
    // A confirmed-nonexistent package IS a determinate answer (a BLOCK) — there
    // is nothing left to check, so this does not count as "couldn't check".
    osvChecked = true;
  }

  // --- Exploit intelligence (KEV + EPSS) on any CVEs found.
  const intelEnabled =
    (options.intel ?? true) && process.env.FIXLY_DISABLE_INTEL !== "1";
  if (intelEnabled && vulnerabilities.length > 0) {
    const intel = await enrichWithIntel(vulnerabilities);
    vulnerabilities = intel.vulnerabilities;
    warnings.push(...intel.warnings);
  }

  // --- Synthesize.
  const counts = emptyCounts();
  const maliciousIds: string[] = [];
  const knownExploitedCves: string[] = [];
  let maxEpss: number | null = null;
  for (const v of vulnerabilities) {
    counts[v.severity]++;
    if (v.malicious) maliciousIds.push(v.osvId);
    if (v.knownExploited && v.cveId) knownExploitedCves.push(v.cveId);
    if (v.epssScore !== null && (maxEpss === null || v.epssScore > maxEpss)) {
      maxEpss = v.epssScore;
    }
  }

  const signals: PackageSignals = {
    exists: popular ? true : registry?.exists ?? null,
    versionExists: registry?.versionExists ?? null,
    popular,
    ageDays: registry?.ageDays ?? null,
    lastPublishDays: registry?.lastPublishDays ?? null,
    weeklyDownloads: registry?.weeklyDownloads ?? null,
    deprecated: registry?.deprecated ?? false,
    hasInstallScripts: registry?.hasInstallScripts ?? null,
    maintainers: registry?.maintainers ?? null,
    typosquatOf: typosquat?.target ?? null,
    nameRiskScore: nameRisk?.score ?? null,
    nameRiskFlagged: nameRisk?.flagged ?? false,
    maliciousIds,
    vulnerabilityCounts: counts,
    knownExploitedCves: [...new Set(knownExploitedCves)],
    maxEpss,
  };

  const base = synthesize(name, effectiveVersion, signals);

  // Fail-safe, not fail-open: a "safe" is only trustworthy if we actually ran
  // the checks that produce BLOCK/CAUTION. If existence couldn't be established
  // (registry unreachable, non-popular) or an enabled OSV lookup couldn't run,
  // downgrade "safe" to "unknown" so callers never mistake a missed check for a
  // clean bill of health. Real CAUTION/BLOCK findings are kept as-is.
  const existenceUnknown = !popular && registry === null;
  let verdict = base.verdict;
  let reasons = base.reasons;
  if (verdict === "safe" && (existenceUnknown || !osvChecked)) {
    verdict = "unknown";
    reasons = [
      existenceUnknown && !osvChecked
        ? "Couldn't verify this package — the npm registry and OSV were both unreachable. This is not a clean bill of health; try again."
        : existenceUnknown
          ? "Couldn't confirm this package exists on npm (registry unreachable), so it can't be cleared as safe."
          : "Couldn't check this package for malware or known vulnerabilities (OSV unreachable), so it can't be cleared as safe.",
    ];
  }

  return {
    package: name,
    version: version ?? null,
    evaluatedVersion: effectiveVersion,
    verdict,
    reasons,
    summary: buildSummary(name, effectiveVersion, verdict, reasons),
    signals,
    vulnerabilities,
    warnings,
  };
}

function synthesize(
  name: string,
  version: string | null,
  s: PackageSignals
): { verdict: VerdictLevel; reasons: string[] } {
  const block: string[] = [];
  const caution: string[] = [];

  // ------------------------------------------------------------- BLOCK tier
  if (s.exists === false) {
    block.push(
      `"${name}" does not exist on npm. AI assistants hallucinate names like this and attackers pre-register them (slopsquatting)` +
        (s.typosquatOf ? ` — did you mean "${s.typosquatOf}"?` : ".")
    );
  }
  if (s.maliciousIds.length > 0) {
    block.push(
      `Flagged as MALICIOUS by OSV (${s.maliciousIds.slice(0, 3).join(", ")}) — this package is malware, not just vulnerable. Do not install.`
    );
  }
  if (s.knownExploitedCves.length > 0) {
    block.push(
      `${s.knownExploitedCves.slice(0, 3).join(", ")} ${s.knownExploitedCves.length === 1 ? "is" : "are"} in CISA's Known Exploited Vulnerabilities catalog — actively exploited in the wild${version ? ` and affecting ${name}@${version}` : ""}. Upgrade before anything else.`
    );
  }
  if (
    s.typosquatOf &&
    s.exists === true &&
    (s.ageDays ?? Infinity) < 90 &&
    (s.weeklyDownloads ?? 0) < LOW_DOWNLOADS_PER_WEEK
  ) {
    block.push(
      `Looks like a typosquat of "${s.typosquatOf}": nearly identical name, only ${s.ageDays} days old, ~${s.weeklyDownloads ?? 0} weekly downloads. The real package is "${s.typosquatOf}".`
    );
  }

  // ----------------------------------------------------------- CAUTION tier
  if (s.versionExists === false) {
    caution.push(
      `Version ${version} does not exist on npm — the requested version may be hallucinated; the latest is different.`
    );
  }
  if (s.typosquatOf && block.length === 0) {
    caution.push(
      `Name is very close to the popular package "${s.typosquatOf}" — double-check this is the one you meant.`
    );
  }
  if (s.vulnerabilityCounts.critical > 0) {
    caution.push(
      `${s.vulnerabilityCounts.critical} critical ${s.vulnerabilityCounts.critical === 1 ? "vulnerability" : "vulnerabilities"}${version ? ` affecting ${name}@${version}` : " on record"}.`
    );
  } else if (s.vulnerabilityCounts.high > 0) {
    caution.push(
      `${s.vulnerabilityCounts.high} high-severity ${s.vulnerabilityCounts.high === 1 ? "vulnerability" : "vulnerabilities"}${version ? ` affecting ${name}@${version}` : " on record"}.`
    );
  }
  if (s.maxEpss !== null && s.maxEpss >= HIGH_EPSS && s.knownExploitedCves.length === 0) {
    caution.push(
      `EPSS predicts a ${(s.maxEpss * 100).toFixed(0)}% chance one of its CVEs is exploited within 30 days.`
    );
  }
  if (!s.popular && s.exists === true && (s.ageDays ?? Infinity) < NEW_PACKAGE_DAYS) {
    caution.push(
      `Brand new on npm (${s.ageDays} ${s.ageDays === 1 ? "day" : "days"} old)${s.hasInstallScripts ? " and it runs install scripts" : ""} — new+obscure is the classic supply-chain-attack profile.`
    );
  } else if (s.hasInstallScripts && !s.popular && (s.weeklyDownloads ?? 0) < LOW_DOWNLOADS_PER_WEEK) {
    caution.push(
      `Runs install scripts (pre/postinstall) with only ~${s.weeklyDownloads ?? 0} weekly downloads — install hooks are how npm malware executes.`
    );
  }
  if (s.deprecated) {
    caution.push(`Deprecated by its maintainer — no future security fixes.`);
  }
  // ML name-risk corroboration: only surfaced when the model is confident AND
  // the package is obscure/new, so it reinforces rather than cries wolf on
  // established packages with unusual names.
  if (
    s.nameRiskFlagged &&
    !s.popular &&
    s.exists === true && // meaningless on a package we can't confirm exists
    block.length === 0 &&
    (s.weeklyDownloads === null || s.weeklyDownloads < LOW_DOWNLOADS_PER_WEEK)
  ) {
    caution.push(
      `Fixly's name-risk model flags this name as resembling known-malicious packages (${((s.nameRiskScore ?? 0) * 100).toFixed(0)}% confidence).`
    );
  }

  if (block.length > 0) return { verdict: "block", reasons: [...block, ...caution] };
  if (caution.length > 0) return { verdict: "caution", reasons: caution };
  return { verdict: "safe", reasons: [] };
}

function buildSummary(
  name: string,
  version: string | null,
  verdict: VerdictLevel,
  reasons: string[]
): string {
  const label = version ? `${name}@${version}` : name;
  if (verdict === "safe") return `${label} looks safe — no malware records, no known vulnerabilities, no red flags.`;
  if (verdict === "caution") return `${label}: proceed with caution — ${reasons[0]}`;
  if (verdict === "unknown") return `${label}: COULD NOT VERIFY — ${reasons[0]}`;
  return `${label}: DO NOT INSTALL — ${reasons[0]}`;
}
