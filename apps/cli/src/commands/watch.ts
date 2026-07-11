// `fixly watch [dir]` — live mode. Watches package.json / package-lock.json
// and re-scans on every change, printing a timestamped grade line with the
// scan-over-scan delta (new / resolved findings). Pair it with an editor or
// `fixly fix --write` in another terminal and you see the grade move in real
// time. Runs until Ctrl+C.

import { watch as fsWatch } from "node:fs";
import {
  buildRemediationPlan,
  compareFindingKeys,
  computeGrade,
  findingKey,
  clearScanCache,
} from "@fixly/core";
import { scanLocalProject } from "../local";
import { bold, dim, gradeColor, gray, green, red, yellow } from "../ui";

export interface WatchOptions {
  dir: string;
}

const WATCHED_FILES = new Set(["package.json", "package-lock.json"]);
const DEBOUNCE_MS = 1000;

function timestamp(): string {
  return new Date().toTimeString().slice(0, 8);
}

async function scanOnce(dir: string, previousKeys: string[] | null): Promise<string[] | null> {
  const result = await scanLocalProject(dir, { includeTransitive: true });
  if (result.error) {
    process.stdout.write(`  ${gray(timestamp())}  ${red("✖")} ${result.error.message}\n`);
    return previousKeys;
  }
  const grade = computeGrade(result);
  const paint = gradeColor(grade.grade);
  const keys = result.vulnerabilities.map(findingKey);

  const parts = [
    `  ${gray(timestamp())}`,
    paint(bold(`${grade.grade} (${grade.score}/100)`)),
    dim("·"),
    `${result.vulnerabilities.length} finding${result.vulnerabilities.length === 1 ? "" : "s"}`,
    dim(`· ${result.totalPackages} pkgs`),
  ];
  const delta = previousKeys !== null ? compareFindingKeys(previousKeys, keys) : null;
  if (delta) {
    if (delta.added.length > 0) parts.push(red(`+${delta.added.length} new`));
    if (delta.resolved.length > 0) parts.push(green(`−${delta.resolved.length} resolved`));
    if (delta.added.length === 0 && delta.resolved.length === 0) parts.push(dim("no change"));
  }
  process.stdout.write(parts.join(" ") + "\n");

  if (delta) {
    for (const key of delta.added) {
      process.stdout.write(`            ${red("+")} ${key.replace("::", " — ")}\n`);
    }
    for (const key of delta.resolved) {
      process.stdout.write(`            ${green("−")} ${key.replace("::", " — ")}\n`);
    }
  }

  const plan = buildRemediationPlan(result);
  if (plan.actions.length > 0) {
    const { after } = plan.forecast;
    process.stdout.write(
      `            ${dim(`fixable to ${after.grade} (${after.score}) — run:`)} ${bold("fixly fix")}\n`
    );
  }
  return keys;
}

export async function watch(options: WatchOptions): Promise<number> {
  process.stdout.write(
    `\n  ${bold("fixly watch")} ${dim("—")} watching ${bold("package.json")} / ${bold("package-lock.json")} in ${options.dir} ${dim("(Ctrl+C to stop)")}\n\n`
  );

  let previousKeys = await scanOnce(options.dir, null);

  let timer: NodeJS.Timeout | null = null;
  let scanning = false;
  let pending = false;

  const rescan = async () => {
    if (scanning) {
      pending = true;
      return;
    }
    scanning = true;
    clearScanCache();
    previousKeys = await scanOnce(options.dir, previousKeys);
    scanning = false;
    if (pending) {
      pending = false;
      void rescan();
    }
  };

  const watcher = fsWatch(options.dir, (_event, filename) => {
    if (!filename || !WATCHED_FILES.has(filename.toString())) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void rescan(), DEBOUNCE_MS);
  });

  // Run until interrupted; the watcher keeps the event loop alive.
  return new Promise<number>((resolve) => {
    process.once("SIGINT", () => {
      watcher.close();
      process.stdout.write(`\n  ${yellow("watch stopped")}\n`);
      resolve(0);
    });
  });
}
