// `fixly vibecheck [dir]` — the 10-second answer: one grade, one headline,
// the three fixes that matter. Zero configuration, full pipeline (transitive
// tree, OSV + NVD, KEV/EPSS intel).

import { computeGrade, countBySeverity } from "@fixly/core";
import { scanLocalProject } from "../local";
import { bold, dim, gray, green, red, yellow, gradeBox } from "../ui";

export interface VibecheckOptions {
  dir: string;
  json: boolean;
}

export async function vibecheck(options: VibecheckOptions): Promise<number> {
  const result = await scanLocalProject(options.dir, { includeTransitive: true });
  if (result.error) {
    process.stderr.write(`${red("✖")} ${result.error.message}\n`);
    return 2;
  }
  const grade = computeGrade(result);

  if (options.json) {
    process.stdout.write(JSON.stringify({ grade, result }, null, 2) + "\n");
    return 0;
  }

  const counts = countBySeverity(result.vulnerabilities);
  const kev = result.vulnerabilities.filter((v) => v.knownExploited).length;
  const malicious = result.vulnerabilities.filter((v) => v.malicious).length;

  const lines: string[] = [];
  lines.push("");
  lines.push(`  ${bold("fixly vibecheck")} ${dim("—")} ${bold(result.repo)}`);
  lines.push("");
  lines.push(gradeBox(grade.grade, grade.score));
  lines.push("");
  lines.push(`  ${grade.headline}`);
  lines.push("");
  lines.push(
    `  ${dim("checked")} ${result.totalPackages} package${result.totalPackages === 1 ? "" : "s"} ${dim(
      `(${result.directPackages} direct + ${result.transitivePackages} transitive)`
    )} ${dim("·")} ${result.vulnerabilities.length} finding${result.vulnerabilities.length === 1 ? "" : "s"} ${dim("·")} ${dim(result.source === "osv+nvd" ? "OSV + NVD" : "OSV")}`
  );

  const badges: string[] = [];
  if (malicious > 0) badges.push(red(bold(`☠ ${malicious} MALICIOUS package${malicious === 1 ? "" : "s"}`)));
  if (kev > 0) badges.push(red(`⚡ ${kev} exploited in the wild (CISA KEV)`));
  if (counts.critical > 0) badges.push(red(`${counts.critical} critical`));
  if (counts.high > 0) badges.push(yellow(`${counts.high} high`));
  if (badges.length > 0) lines.push(`  ${badges.join(dim("  ·  "))}`);

  if (grade.topFixes.length > 0) {
    lines.push("");
    lines.push(`  ${bold("Fix these first:")}`);
    for (const fix of grade.topFixes) {
      lines.push(
        `  ${yellow("→")} ${bold(fix.package)}@${fix.installedVersion} ${dim(`(${fix.reason})`)}`
      );
      if (fix.command) lines.push(`      ${green("$")} ${fix.command}`);
    }
  }

  for (const w of result.warnings) lines.push(`  ${gray(`⚠ ${w}`)}`);

  lines.push("");
  lines.push(
    `  ${dim("share it:")} vibecheck ${grade.grade} (${grade.score}/100) on ${result.repo} ${dim("·")} fixly vibecheck`
  );
  lines.push("");

  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
