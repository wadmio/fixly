// SARIF 2.1.0 output — the lingua franca of code-scanning CI. Uploading this
// to GitHub code scanning renders Fixly findings natively on PRs.

import type { ScanResult, ScanVulnerability } from "@fixly/core";

type SarifLevel = "error" | "warning" | "note";

function levelFor(v: ScanVulnerability): SarifLevel {
  if (v.malicious || v.knownExploited) return "error";
  switch (v.severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

function messageFor(v: ScanVulnerability): string {
  const poc = !v.knownExploited && v.pocCount ? `, ${v.pocCount} public PoC(s)` : "";
  const parts = [
    `${v.package}@${v.installedVersion}: ${v.title}`,
    `[${v.severity}${v.cveId ? `, ${v.cveId}` : ""}${v.knownExploited ? ", exploited in the wild (CISA KEV)" : ""}${poc}${v.malicious ? ", MALICIOUS PACKAGE" : ""}]`,
  ];
  if (v.fixedVersion) parts.push(`Fix: upgrade to ${v.fixedVersion}.`);
  if (v.dependencyType === "transitive") parts.push("(transitive dependency)");
  return parts.join(" ");
}

/** Convert a scan into a minimal, valid SARIF 2.1.0 log. */
export function toSarif(result: ScanResult, version: string): object {
  const rules = new Map<string, object>();
  for (const v of result.vulnerabilities) {
    if (rules.has(v.osvId)) continue;
    rules.set(v.osvId, {
      id: v.osvId,
      name: v.osvId,
      shortDescription: { text: v.title || v.osvId },
      helpUri: v.references[0] ?? `https://osv.dev/vulnerability/${v.osvId}`,
      properties: { severity: v.severity, cve: v.cveId ?? undefined },
    });
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Fixly",
            informationUri: "https://github.com/wadmio/fixly",
            version,
            rules: [...rules.values()],
          },
        },
        results: result.vulnerabilities.map((v) => ({
          ruleId: v.osvId,
          level: levelFor(v),
          message: { text: messageFor(v) },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: v.dependencyType === "transitive" ? "package-lock.json" : "package.json",
                },
              },
            },
          ],
          properties: {
            package: v.package,
            installedVersion: v.installedVersion,
            fixedVersion: v.fixedVersion ?? undefined,
            dependencyType: v.dependencyType,
            knownExploited: v.knownExploited,
            kevDateAdded: v.kevDateAdded ?? undefined,
            epssScore: v.epssScore ?? undefined,
            pocCount: v.pocCount ?? undefined,
            malicious: v.malicious,
          },
        })),
      },
    ],
  };
}
