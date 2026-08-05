// Fix Brief — deterministic, paste-ready remediation text for an AI coding
// agent or a teammate. Pure and vscode-free (same pattern as advice.ts /
// panel-render.ts) so the builders are unit-testable in plain vitest. Fixly
// only COPIES this text; it never edits files, never runs npm, never applies
// an override — the reader of the brief does, then Fixly's next scan verifies.

import type {
  Remediation,
  RemediationAction,
  RemediationPlan,
  ScanResult,
  ScanVulnerability,
  UnfixableFinding,
} from "@fixly/core";

const SEVERITY_ORDER: Record<ScanVulnerability["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

/** All findings for one package@installedVersion, worst first, id-stable. */
function findingsFor(
  result: ScanResult,
  pkg: string,
  installedVersion: string
): ScanVulnerability[] {
  return result.vulnerabilities
    .filter((v) => v.package === pkg && v.installedVersion === installedVersion)
    .sort(
      (a, b) =>
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        a.osvId.localeCompare(b.osvId)
    );
}

function advisoryLine(v: ScanVulnerability): string {
  const parts: string[] = [v.osvId];
  if (v.cveId) parts.push(`(${v.cveId})`);
  const flags: string[] = [v.severity];
  if (v.cvssScore !== null) flags.push(`CVSS ${v.cvssScore.toFixed(1)}`);
  if (v.malicious) flags.push("MALICIOUS");
  if (v.knownExploited) flags.push("exploited in the wild (CISA KEV)");
  return `  - ${parts.join(" ")} — ${flags.join(", ")} — ${v.title}`;
}

function advisoryBlock(vulns: ScanVulnerability[]): string[] {
  const n = vulns.length;
  return [
    `Advisories (${n}):`,
    ...vulns.map(advisoryLine),
  ];
}

/** The exact `overrides` JSON for a transitive pin — copy-paste into package.json. */
function overridesJson(pkg: string, target: string): string {
  return JSON.stringify({ overrides: { [pkg]: target } }, null, 2);
}

function actionSection(result: ScanResult, action: RemediationAction): string[] {
  const vulns = findingsFor(result, action.package, action.installedVersion);
  const lines: string[] = [];

  if (action.kind === "remove") {
    lines.push(`## ${action.package}@${action.installedVersion} — REMOVE (known malicious)`);
    lines.push(...advisoryBlock(vulns));
    lines.push(`Action: remove — this is malware, not a bug. Never upgrade it.`);
    lines.push(`Run:`);
    lines.push(`    ${action.command}`);
    return lines;
  }

  const res = action.resolution;
  const target = action.targetVersion ?? "?";
  const jump = res?.semverDistance ?? null;
  const risk = res?.risk ?? "elevated";
  const label = action.kind === "override" ? "transitive — pin via npm overrides" : "direct upgrade";
  lines.push(
    `## ${action.package}@${action.installedVersion} → ${target} — ${label} (${jump ? `${jump.toLowerCase()} jump` : "jump size unknown"}, ${risk} risk)`
  );
  lines.push(...advisoryBlock(vulns.filter((v) => v.fixedVersion !== null)));
  lines.push(`Minimum safe target: ${target}`);
  if (res) lines.push(`Resolution path: ${res.path}`);
  lines.push(`Semver jump: ${jump ?? "unknown — could not be determined; review the changelog before upgrading"}`);
  lines.push(`Risk: ${risk}`);
  if (res) lines.push(`Why: ${res.rationale}`);

  if (action.kind === "override") {
    lines.push(`Add to package.json (exact JSON to merge):`);
    for (const l of overridesJson(action.package, target).split("\n")) {
      lines.push(`    ${l}`);
    }
    lines.push(`then run:`);
    lines.push(`    npm install`);
    lines.push(`(or as one command: ${action.command})`);
  } else {
    lines.push(`Run:`);
    lines.push(`    ${action.command}`);
  }

  const leftover = vulns.filter((v) => v.fixedVersion === null);
  if (leftover.length > 0) {
    lines.push(
      `Note: ${leftover.length} ${leftover.length === 1 ? "advisory" : "advisories"} on this package (${leftover
        .map((v) => v.osvId)
        .join(", ")}) ${leftover.length === 1 ? "has" : "have"} no published fix and will remain after this change.`
    );
  }
  return lines;
}

function blockedSection(result: ScanResult, blocked: Remediation): string[] {
  const vulns = findingsFor(result, blocked.package, blocked.installedVersion).filter(
    (v) => v.fixedVersion !== null
  );
  const lines: string[] = [
    `## ${blocked.package}@${blocked.installedVersion} — BLOCKED_BY_PARENT (no safe edit exists)`,
    ...advisoryBlock(vulns),
  ];
  lines.push(
    `A fixed release${blocked.targetVersion ? ` (${blocked.targetVersion})` : ""} exists, but a dependent's declared version range forbids installing it:`
  );
  for (const b of blocked.blockers) {
    lines.push(`  - ${b.dependent} requires "${b.range}"`);
  }
  lines.push(`Why: ${blocked.rationale}`);
  lines.push(
    `Do NOT force an incompatible version. Options: upgrade or replace the blocking dependent so its range allows the fix, or wait for a compatible release, then rescan.`
  );
  return lines;
}

function unfixableSection(entries: UnfixableFinding[]): string[] {
  // Group by package@version, preserving plan order.
  const seen = new Set<string>();
  const lines: string[] = [`## No fix available yet (NO_FIX_AVAILABLE)`];
  for (const u of entries) {
    const key = `${u.package}@${u.installedVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const ids = entries
      .filter((e) => e.package === u.package && e.installedVersion === u.installedVersion)
      .map((e) => `${e.osvId} (${e.severity})`)
      .join(", ");
    lines.push(`  - ${key} — ${ids}`);
  }
  lines.push(
    `No fixed release has been published for these advisories — a legitimate state, not an error. Re-scan later, or consider replacing the package.`
  );
  return lines;
}

function header(result: ScanResult, plan: RemediationPlan): string[] {
  const f = plan.forecast;
  return [
    `# Fixly fix brief — ${result.repo}`,
    `Scanned: ${result.scannedAt} · ${plan.totalFindings} ${plan.totalFindings === 1 ? "finding" : "findings"} across ${result.totalPackages} packages (${result.directPackages} direct, ${result.transitivePackages} transitive)`,
    `Fixly Score: ${f.before.grade} (${f.before.score}/100) → ${f.after.grade} (${f.after.score}/100) if every action below is applied`,
    ``,
  ];
}

const FOOTER = [
  ``,
  `## After applying`,
  `Apply the changes above yourself (or hand this brief to your coding agent), then run \`npm install\` and rescan with Fixly to verify — the lock-file watcher rescans automatically and reports which findings were resolved, which remain, and whether anything new was introduced.`,
  `Fixly analyzes and verifies, never modifies — nothing in this brief was applied automatically.`,
];

/**
 * The complete fix brief for a scan: every planned action in plan order
 * (malware removals first, then by Fixly Score points recovered), then blocked
 * packages, then findings with no published fix. Deterministic for a given
 * (result, plan) — safe to snapshot-test and diff between scans.
 */
export function buildFixBrief(result: ScanResult, plan: RemediationPlan): string {
  const lines: string[] = header(result, plan);

  if (
    plan.actions.length === 0 &&
    plan.blocked.length === 0 &&
    plan.unfixable.length === 0
  ) {
    lines.push(`No known vulnerabilities — nothing to fix.`);
    return lines.join("\n");
  }

  // Unfixed leftovers on a package that also has an action are noted inside
  // that action's section — the standalone list is only for versions no
  // action covers, so nothing is stated twice.
  const covered = new Set(plan.actions.map((a) => `${a.package}@${a.installedVersion}`));
  const standaloneUnfixable = plan.unfixable.filter(
    (u) => !covered.has(`${u.package}@${u.installedVersion}`)
  );

  const sections: string[][] = [];
  for (const action of plan.actions) sections.push(actionSection(result, action));
  for (const blocked of plan.blocked) sections.push(blockedSection(result, blocked));
  if (standaloneUnfixable.length > 0)
    sections.push(unfixableSection(standaloneUnfixable));

  lines.push(sections.map((s) => s.join("\n")).join("\n\n"));
  lines.push(...FOOTER);
  return lines.join("\n");
}

/**
 * The fix brief for ONE package (all installed versions of it): its actions,
 * blocked states, and unfixed advisories, with the same closing instruction.
 * Returns null when the scan has no findings for that package.
 */
export function buildPackageBrief(
  result: ScanResult,
  plan: RemediationPlan,
  packageName: string
): string | null {
  const actions = plan.actions.filter((a) => a.package === packageName);
  const blocked = plan.blocked.filter((b) => b.package === packageName);
  const unfixable = plan.unfixable.filter((u) => u.package === packageName);
  // Unfixed leftovers on a package that ALSO has an action are already noted
  // inside the action section — only render the standalone unfixable section
  // for versions no action covers.
  const covered = new Set(actions.map((a) => `${a.package}@${a.installedVersion}`));
  const standaloneUnfixable = unfixable.filter(
    (u) => !covered.has(`${u.package}@${u.installedVersion}`)
  );

  if (actions.length === 0 && blocked.length === 0 && standaloneUnfixable.length === 0) {
    return null;
  }

  const lines: string[] = [
    `# Fixly fix brief — ${packageName} (from scan of ${result.repo}, ${result.scannedAt})`,
    ``,
  ];
  const sections: string[][] = [];
  for (const action of actions) sections.push(actionSection(result, action));
  for (const b of blocked) sections.push(blockedSection(result, b));
  if (standaloneUnfixable.length > 0)
    sections.push(unfixableSection(standaloneUnfixable));
  lines.push(sections.map((s) => s.join("\n")).join("\n\n"));
  lines.push(...FOOTER);
  return lines.join("\n");
}
