// `fixly scan [target]` — the CI workhorse. Target is a local directory
// (default: cwd) or a public GitHub URL. Human output by default; --json and
// --sarif for machines; --fail-on gates pipelines with exit code 1.

import { runScan, parseGitHubUrl, computeGrade, countBySeverity, type ScanResult, type Severity } from "@fixly/core";
import { scanLocalProject } from "../local";
import { toSarif } from "../sarif";
import { bold, dim, gray, green, red, severityLabel, gradeColor } from "../ui";

export type FailOn = "critical" | "high" | "medium" | "low" | "any" | "never";

const FAIL_RANK: Record<Exclude<FailOn, "never" | "any">, Severity[]> = {
  critical: ["critical"],
  high: ["critical", "high"],
  medium: ["critical", "high", "medium"],
  low: ["critical", "high", "medium", "low"],
};

export interface ScanOptions {
  target: string;
  json: boolean;
  sarif: boolean;
  failOn: FailOn;
  transitive: boolean;
  version: string;
}

function shouldFail(result: ScanResult, failOn: FailOn): boolean {
  if (failOn === "never") return false;
  // Malware always fails a gated scan, regardless of threshold.
  if (result.vulnerabilities.some((v) => v.malicious)) return true;
  if (failOn === "any") return result.vulnerabilities.length > 0;
  const severities = new Set<Severity>(FAIL_RANK[failOn]);
  return result.vulnerabilities.some((v) => severities.has(v.severity));
}

function findingLine(result: ScanResult): string[] {
  return result.vulnerabilities.map((v) => {
    const flags: string[] = [];
    if (v.malicious) flags.push(red(bold("MALICIOUS")));
    if (v.knownExploited) flags.push(red("KEV"));
    else if (v.epssScore !== null && v.epssScore >= 0.1) {
      flags.push(`EPSS ${(v.epssScore * 100).toFixed(0)}%`);
    }
    if (v.dependencyType === "transitive") flags.push(dim("transitive"));
    return [
      `  ${severityLabel(v.severity)}`,
      `${bold(v.package)}@${v.installedVersion}`,
      dim(v.cveId ?? v.osvId),
      v.fixedVersion ? green(`→ ${v.fixedVersion}`) : dim("no fix"),
      flags.length ? `[${flags.join(", ")}]` : "",
    ]
      .filter(Boolean)
      .join(" ");
  });
}

export async function scan(options: ScanOptions): Promise<number> {
  const isUrl = parseGitHubUrl(options.target) !== null;
  const result = isUrl
    ? await runScan(options.target)
    : await scanLocalProject(options.target, { includeTransitive: options.transitive });

  if (result.error) {
    if (options.json) process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    else process.stderr.write(`${red("✖")} ${result.error.message}\n`);
    return 2;
  }

  if (options.sarif) {
    process.stdout.write(JSON.stringify(toSarif(result, options.version), null, 2) + "\n");
  } else if (options.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    const grade = computeGrade(result);
    const counts = countBySeverity(result.vulnerabilities);
    const lines: string[] = [];
    lines.push("");
    lines.push(`  ${bold("fixly scan")} ${dim("—")} ${bold(result.repo)}`);
    lines.push(
      `  ${result.totalPackages} packages ${dim(
        `(${result.directPackages} direct + ${result.transitivePackages} transitive)`
      )} ${dim("·")} ${result.resolvedPackages} checked ${dim("·")} ${dim(result.source === "osv+nvd" ? "OSV + NVD" : "OSV")}`
    );
    lines.push("");

    if (result.vulnerabilities.length === 0) {
      lines.push(`  ${green("✔ No known vulnerabilities.")}`);
    } else {
      lines.push(
        `  ${bold(String(result.vulnerabilities.length))} findings ${dim(
          `(${counts.critical}C ${counts.high}H ${counts.medium}M ${counts.low}L ${counts.unknown}U)`
        )} ${dim("·")} grade ${gradeColor(grade.grade)(bold(grade.grade))} ${dim(`(${grade.score}/100)`)}`
      );
      lines.push("");
      lines.push(...findingLine(result));
    }

    for (const w of result.warnings) lines.push(`  ${gray(`⚠ ${w}`)}`);
    lines.push("");
    process.stdout.write(lines.join("\n") + "\n");
  }

  return shouldFail(result, options.failOn) ? 1 : 0;
}
