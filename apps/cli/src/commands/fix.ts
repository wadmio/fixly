// `fixly fix [dir]` — the remediation engine at the terminal. Scans, builds
// the ordered fix plan with its Grade Forecast, and prints it as a dry run.
// `--write` applies the plan to package.json (direct bumps keep your `^`/`~`
// style, transitive pins land in `overrides`, malware is deleted) — then you
// run your package manager to realize it. We edit the manifest; we never run
// installs for you.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  applyRemediationPlan,
  buildRemediationPlan,
  type RemediationAction,
} from "@fixly/core";
import { scanLocalProject } from "../local";
import { bold, dim, gradeColor, gray, green, red, yellow } from "../ui";

export interface FixOptions {
  dir: string;
  json: boolean;
  /** Apply the plan to package.json instead of only printing it. */
  write: boolean;
}

function actionGlyph(action: RemediationAction): string {
  switch (action.kind) {
    case "remove":
      return red(bold("✖ remove "));
    case "override":
      return yellow("◆ override");
    default:
      return green("↑ upgrade ");
  }
}

export async function fix(options: FixOptions): Promise<number> {
  const result = await scanLocalProject(options.dir, { includeTransitive: true });
  if (result.error) {
    process.stderr.write(`${red("✖")} ${result.error.message}\n`);
    return 2;
  }
  const plan = buildRemediationPlan(result);

  if (options.json && !options.write) {
    process.stdout.write(JSON.stringify(plan, null, 2) + "\n");
    return 0;
  }

  const lines: string[] = [];
  const { before, after } = plan.forecast;
  const paintBefore = gradeColor(before.grade);
  const paintAfter = gradeColor(after.grade);

  lines.push("");
  lines.push(`  ${bold("fixly fix")} ${dim("—")} ${bold(result.repo)}`);
  lines.push("");

  if (plan.actions.length === 0) {
    lines.push(
      plan.totalFindings === 0
        ? `  ${green("✔")} nothing to fix — ${result.totalPackages} packages checked, no findings.`
        : `  ${yellow("⚠")} ${plan.totalFindings} finding${plan.totalFindings === 1 ? "" : "s"}, but none have a published fix yet. Nothing to apply.`
    );
    lines.push("");
    process.stdout.write(lines.join("\n") + "\n");
    return 0;
  }

  lines.push(
    `  ${bold("Grade Forecast:")} ${paintBefore(bold(`${before.grade} (${before.score})`))} ${dim("→")} ${paintAfter(bold(`${after.grade} (${after.score})`))} ${dim(`if you apply all ${plan.actions.length} action${plan.actions.length === 1 ? "" : "s"}`)}`
  );
  lines.push("");

  for (const action of plan.actions) {
    const move = action.targetVersion
      ? `${action.installedVersion} ${dim("→")} ${action.targetVersion}`
      : action.installedVersion;
    lines.push(`  ${actionGlyph(action)} ${bold(action.package)} ${move}  ${dim(`+${action.pointsRecovered} pts`)}`);
    lines.push(`      ${dim(action.reason)}`);
    lines.push(`      ${green("$")} ${action.command}`);
  }

  if (plan.unfixable.length > 0) {
    lines.push("");
    lines.push(
      `  ${gray(`⚠ ${plan.unfixable.length} finding${plan.unfixable.length === 1 ? "" : "s"} without a published fix (kept in the forecast):`)}`
    );
    for (const u of plan.unfixable) {
      lines.push(`      ${gray(`${u.package}@${u.installedVersion} — ${u.osvId} (${u.severity})`)}`);
    }
  }

  if (!options.write) {
    lines.push("");
    lines.push(`  ${dim("dry run — pass")} ${bold("--write")} ${dim("to apply this plan to package.json")}`);
    lines.push("");
    process.stdout.write(lines.join("\n") + "\n");
    return 0;
  }

  // --write: rewrite package.json in place, then hand off to the package manager.
  const manifestPath = join(options.dir, "package.json");
  const manifestText = await readFile(manifestPath, "utf8");
  const applied = applyRemediationPlan(manifestText, plan);
  await writeFile(manifestPath, applied.text, "utf8");

  lines.push("");
  lines.push(`  ${green("✔")} ${bold("package.json updated:")}`);
  for (const change of applied.changes) lines.push(`      ${change}`);
  for (const skippedAction of applied.skipped) {
    lines.push(
      `      ${gray(`skipped ${skippedAction.package} (not declared in package.json — run: ${skippedAction.command})`)}`
    );
  }
  lines.push("");
  lines.push(`  ${bold("Next:")} ${green("$")} npm install ${dim("&&")} fixly vibecheck ${dim("— verify the forecast")}`);
  lines.push("");
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
