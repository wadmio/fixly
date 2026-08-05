// Pure advice rendering for the in-editor surfaces — deliberately free of any
// `vscode` import so it's unit-testable in plain vitest (same pattern as
// panel-render.ts). Turns the resolution engine's structured Remediation data
// into: a diagnostic tier (risk + CVSS, not CVSS alone), a one-line diagnostic
// message, and a markdown hover card. Fixly analyzes and verifies, never
// modifies — everything here is advice text.

import type {
  RemediationAction,
  RemediationPlan,
  Remediation,
  ScanResult,
  ScanVulnerability,
  Severity,
} from "@fixly/core";

/** Squiggle tier, mapped to vscode.DiagnosticSeverity by the caller. */
export type DiagnosticTier = "error" | "warning" | "info" | "hint";

export interface PackageAdvice {
  package: string;
  installedVersion: string;
  /** This package's findings, worst first. */
  vulns: ScanVulnerability[];
  tier: DiagnosticTier;
  /** One-line diagnostic message (finding summary + remediation clause). */
  message: string;
  /** Full remediation card as markdown (hover). */
  hoverMarkdown: string;
  /** Advisory id + first reference of the worst finding (diagnostic code link). */
  worstOsvId: string;
  worstReference: string | null;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

/** Escape characters that would break out of our markdown structure. */
function md(text: string): string {
  return text.replace(/([\\`*_[\]<>])/g, "\\$1");
}

/**
 * The squiggle tier maps to fix risk + CVSS, not CVSS alone:
 * - malicious / known-exploited, or critical/high CVSS → error
 * - medium CVSS → warning
 * - low CVSS but an elevated remediation (major jump, unmeasurable jump, or
 *   blocked) → warning — acting on it is consequential, so it must be seen
 * - low CVSS with a calm fix (patch/minor, or nothing to do) → info
 * - unknown severity → hint (info when the remediation is elevated)
 */
export function diagnosticTier(
  vulns: ScanVulnerability[],
  action: RemediationAction | undefined,
  blocked: Remediation | undefined
): DiagnosticTier {
  if (vulns.some((v) => v.malicious || v.knownExploited)) return "error";
  const worst = vulns[0].severity;
  if (worst === "critical" || worst === "high") return "error";
  if (worst === "medium") return "warning";

  const elevated =
    blocked !== undefined || action?.resolution?.risk === "elevated";
  if (worst === "low") return elevated ? "warning" : "info";
  return elevated ? "info" : "hint";
}

/** The remediation clause of the one-line diagnostic message. */
function remediationClause(
  installedVersion: string,
  action: RemediationAction | undefined,
  blocked: Remediation | undefined
): string {
  if (blocked) {
    const b = blocked.blockers[0];
    return b
      ? `A fix exists but ${b.dependent} requires "${b.range}" — blocked; no safe upgrade from here.`
      : `A fix exists but a dependent's version range forbids it — blocked.`;
  }
  if (!action) return "No fixed release published yet.";
  if (action.kind === "remove") {
    return "Known MALICIOUS package — remove it, do not upgrade it.";
  }
  const target = action.targetVersion ?? "?";
  const distance = action.resolution?.semverDistance ?? null;
  if (distance === "MAJOR") {
    return `Fix requires major bump ${installedVersion} → ${target} — breaking API changes likely.`;
  }
  if (distance === null) {
    return `Patched in ${target} — jump size undetermined, review before upgrading.`;
  }
  return `Patched in ${target} — ${distance.toLowerCase()} bump, direct dep, low risk.`;
}

/** Markdown remediation section of the hover card. */
function remediationMarkdown(
  action: RemediationAction | undefined,
  blocked: Remediation | undefined,
  unfixedCount: number
): string {
  const lines: string[] = [];

  if (blocked) {
    lines.push(`**Remediation — blocked by parent** _(no safe edit exists)_`);
    lines.push("");
    lines.push(md(blocked.rationale));
    if (blocked.blockers.length > 0) {
      lines.push("");
      for (const b of blocked.blockers) {
        lines.push(`- ${md(b.dependent)} requires \`${b.range}\``);
      }
    }
    return lines.join("\n");
  }

  if (!action) {
    lines.push(`**Remediation — no fix available yet** _(a legitimate state, not an error)_`);
    lines.push("");
    lines.push(
      "No fixed release has been published for these advisories. Re-scan later, or consider replacing the package."
    );
    return lines.join("\n");
  }

  if (action.kind === "remove") {
    lines.push(`**Remediation — remove** _(known malicious)_`);
    lines.push("");
    lines.push("This is malware, not a bug — never upgrade it, remove it:");
    lines.push("");
    lines.push("```sh");
    lines.push(action.command);
    lines.push("```");
    return lines.join("\n");
  }

  const res = action.resolution;
  const distance = res?.semverDistance ? res.semverDistance.toLowerCase() : "unknown-size";
  const risk = res?.risk ?? "elevated";
  const label = action.kind === "override" ? "override (transitive)" : "direct upgrade";
  lines.push(`**Remediation — ${label}** _(${distance} bump, ${risk} risk)_`);
  lines.push("");
  if (res) lines.push(md(res.rationale));
  lines.push("");
  lines.push("```sh");
  lines.push(action.command);
  lines.push("```");
  if (unfixedCount > 0) {
    lines.push("");
    lines.push(
      `_${unfixedCount} ${unfixedCount === 1 ? "advisory" : "advisories"} on this package ${unfixedCount === 1 ? "has" : "have"} no published fix yet and will remain after the upgrade._`
    );
  }
  return lines.join("\n");
}

function hoverMarkdown(
  pkg: string,
  vulns: ScanVulnerability[],
  action: RemediationAction | undefined,
  blocked: Remediation | undefined
): string {
  const first = vulns[0];
  const n = vulns.length;
  const lines: string[] = [
    `**${md(pkg)}@${md(first.installedVersion)}** — ${n} ${n === 1 ? "advisory" : "advisories"} (worst: **${first.severity}**)`,
    "",
  ];

  for (const v of vulns.slice(0, 4)) {
    const id = v.references[0] ? `[${md(v.osvId)}](${v.references[0]})` : md(v.osvId);
    const cve = v.cveId ? ` · ${md(v.cveId)}` : "";
    const flags = v.malicious ? " · **MALICIOUS**" : v.knownExploited ? " · **exploited in the wild (KEV)**" : "";
    lines.push(`- **${v.severity}** ${id}${cve}${flags} — ${md(v.title)}`);
  }
  if (vulns.length > 4) lines.push(`- _…and ${vulns.length - 4} more_`);
  lines.push("");

  const unfixedCount =
    action && action.kind !== "remove"
      ? vulns.filter((v) => v.fixedVersion === null).length
      : 0;
  lines.push(remediationMarkdown(action, blocked, unfixedCount));
  lines.push("");
  lines.push("_Fixly analyzes and verifies, never modifies — apply this yourself (or hand it to your AI agent); Fixly rescans and verifies once the lock file changes._");
  return lines.join("\n");
}

/**
 * Build per-package advice for every vulnerable DIRECT dependency (transitive
 * findings have no line in package.json — they stay in the report panel).
 * The plan should come from `buildRemediationPlan(result, { graph })` so
 * blocked/override analysis reflects the real dependency graph.
 */
export function adviceForScan(
  result: ScanResult,
  plan: RemediationPlan
): Map<string, PackageAdvice> {
  const byPackage = new Map<string, ScanVulnerability[]>();
  for (const v of result.vulnerabilities) {
    if (v.dependencyType === "transitive") continue;
    const list = byPackage.get(v.package);
    if (list) list.push(v);
    else byPackage.set(v.package, [v]);
  }

  const advice = new Map<string, PackageAdvice>();
  for (const [pkg, vulns] of byPackage) {
    vulns.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    const worst = vulns[0];
    const action = plan.actions.find((a) => a.package === pkg);
    const blocked = plan.blocked.find((b) => b.package === pkg);

    const count = vulns.length;
    const summary = `${pkg}@${worst.installedVersion}: ${count} known ${count === 1 ? "vulnerability" : "vulnerabilities"} — worst is ${worst.severity} (${worst.cveId ?? worst.osvId}).`;

    advice.set(pkg, {
      package: pkg,
      installedVersion: worst.installedVersion,
      vulns,
      tier: diagnosticTier(vulns, action, blocked),
      message: `${summary} ${remediationClause(worst.installedVersion, action, blocked)}`,
      hoverMarkdown: hoverMarkdown(pkg, vulns, action, blocked),
      worstOsvId: worst.osvId,
      worstReference: worst.references[0] ?? null,
    });
  }
  return advice;
}
