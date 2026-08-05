// `fixly fix [dir]` — the remediation engine at the terminal. Scans, builds
// the ordered fix plan with its Grade Forecast, and prints it as precise,
// copy-paste advice: exact target versions, override entries, and the points
// each action recovers. Fixly analyzes and verifies, never modifies — apply
// the plan by hand (or hand it to your AI agent), run your package manager,
// then `fixly vibecheck` to verify the forecast.

import { buildRemediationPlan, type RemediationAction } from "@fixly/core";
import { scanLocalProject } from "../local";
import { bold, dim, gradeColor, gray, green, red, yellow } from "../ui";

export interface FixOptions {
  dir: string;
  json: boolean;
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

  if (options.json) {
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
        : `  ${yellow("⚠")} ${plan.totalFindings} finding${plan.totalFindings === 1 ? "" : "s"}, but none have a published fix yet.`
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

  lines.push("");
  lines.push(
    `  ${dim("Fixly analyzes and verifies, never modifies. Apply the commands above (or paste")}`
  );
  lines.push(
    `  ${dim("them into your AI agent), then:")} ${green("$")} npm install ${dim("&&")} fixly vibecheck ${dim("— verify the forecast")}`
  );
  lines.push("");
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}
