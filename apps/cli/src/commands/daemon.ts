// `fixly daemon [dir ...]` — the real-time remediation engine.
//
// Two triggers feed one serialized scan path per project:
//   1. file events — fs.watch on package.json/package-lock.json (~1s), so a
//      vulnerable dependency is caught the moment it lands on disk;
//   2. the advisory clock — an interval re-scan (default 10 min), so a CVE
//      published overnight for a package you already have surfaces in minutes.
//
// Unlike `fixly watch` (which only tells you), the daemon REMEDIATES by
// default: it applies the fix plan to package.json, runs npm install, then
// re-scans to VERIFY the findings are gone, and reports the measured
// time-to-remediate (MTTR: change detected on disk → fix verified).
// `--notify-only` restores alert-only behavior. See docs/daemon.md.

import { spawn } from "node:child_process";
import { watch as fsWatch, type FSWatcher } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import {
  applyRemediationPlan,
  buildRemediationPlan,
  clearScanCache,
  computeGrade,
  findingKey,
  type RemediationPlan,
  type ScanResult,
  type ScanVulnerability,
} from "@fixly/core";
import { scanLocalProject } from "../local";
import {
  diffAgainstSnapshot,
  loadState,
  saveState,
  snapshotFromScan,
  type DaemonState,
  type ProjectSnapshot,
} from "../daemon-state";
import { notifyDesktop, sendWebhook } from "../notify";
import { bold, dim, gradeColor, gray, green, red, yellow } from "../ui";

export interface DaemonOptions {
  dirs: string[];
  intervalMinutes: number;
  /** Detect + alert, never touch files (phase-1 alert mode). */
  notifyOnly: boolean;
  /** Rewrite package.json but skip `npm install` (verification impossible). */
  noInstall: boolean;
  webhook: string | null;
  desktop: boolean;
  json: boolean;
}

const WATCHED_FILES = new Set(["package.json", "package-lock.json"]);
const DEBOUNCE_MS = 1_000;
const FAILURES_BEFORE_ALERT = 3;

/** Side effects the remediation loop performs, injectable for tests. */
export interface DaemonIO {
  scan(dir: string): Promise<ScanResult>;
  readManifest(dir: string): Promise<string>;
  writeManifest(dir: string, text: string): Promise<void>;
  runInstall(dir: string): Promise<{ code: number; output: string }>;
  now(): number;
}

function runNpmInstall(dir: string): Promise<{ code: number; output: string }> {
  // npm is a .cmd shim on Windows, which requires a shell (same handling as
  // guard's passthrough). Output is captured, not streamed — the daemon's
  // terminal stays a clean event log; failures print the tail.
  const windows = process.platform === "win32";
  return new Promise((resolvePromise) => {
    const child = windows
      ? spawn("npm install --no-audit --no-fund", {
          cwd: dir,
          stdio: ["ignore", "pipe", "pipe"],
          shell: true,
        })
      : spawn("npm", ["install", "--no-audit", "--no-fund"], {
          cwd: dir,
          stdio: ["ignore", "pipe", "pipe"],
        });
    let output = "";
    child.stdout?.on("data", (d: Buffer) => (output += String(d)));
    child.stderr?.on("data", (d: Buffer) => (output += String(d)));
    child.on("close", (code) => resolvePromise({ code: code ?? 1, output }));
    child.on("error", (err) => resolvePromise({ code: 1, output: err.message }));
  });
}

export const realIO: DaemonIO = {
  scan: (dir) => {
    // The in-memory scan cache would serve a stale result inside its 5-min
    // TTL — every daemon scan must observe the current disk + OSV state.
    clearScanCache();
    return scanLocalProject(dir, { includeTransitive: true, nvd: false });
  },
  readManifest: (dir) => readFile(join(dir, "package.json"), "utf8"),
  writeManifest: (dir, text) => writeFile(join(dir, "package.json"), text, "utf8"),
  runInstall: (dir) => runNpmInstall(dir),
  now: () => Date.now(),
};

export interface RemediationOutcome {
  /** package.json was rewritten. */
  applied: boolean;
  /** npm install ran and succeeded (always false with --no-install). */
  installed: boolean;
  /** The re-scan confirmed the triggering findings are gone. */
  verified: boolean;
  plan: RemediationPlan;
  changes: string[];
  /** Change detected on disk → fix verified (or manifest written when
   *  --no-install). null when nothing was applied. */
  mttrMs: number | null;
  verifyResult: ScanResult | null;
  failure: string | null;
}

/**
 * The remediation step: apply the plan to package.json, realize it with
 * npm install, re-scan to verify. Pure orchestration over injected IO.
 */
export async function remediate(
  dir: string,
  result: ScanResult,
  triggeredBy: ScanVulnerability[],
  opts: { noInstall: boolean; detectedAt: number },
  io: DaemonIO
): Promise<RemediationOutcome> {
  const plan = buildRemediationPlan(result);
  const outcome: RemediationOutcome = {
    applied: false,
    installed: false,
    verified: false,
    plan,
    changes: [],
    mttrMs: null,
    verifyResult: null,
    failure: null,
  };

  if (plan.actions.length === 0) {
    outcome.failure = "no published fix exists yet for the detected findings";
    return outcome;
  }

  try {
    const manifestText = await io.readManifest(dir);
    const applied = applyRemediationPlan(manifestText, plan);
    await io.writeManifest(dir, applied.text);
    outcome.applied = true;
    outcome.changes = applied.changes;
  } catch (err) {
    outcome.failure = `could not rewrite package.json: ${err instanceof Error ? err.message : String(err)}`;
    return outcome;
  }

  if (opts.noInstall) {
    // Without the install the lock file still pins the old versions, so a
    // verify scan would (correctly) still report the findings. Stop honestly.
    outcome.mttrMs = io.now() - opts.detectedAt;
    return outcome;
  }

  const install = await io.runInstall(dir);
  if (install.code !== 0) {
    const tail = install.output.trim().split("\n").slice(-5).join("\n");
    outcome.failure = `npm install failed (exit ${install.code}):\n${tail}`;
    return outcome;
  }
  outcome.installed = true;

  try {
    outcome.verifyResult = await io.scan(dir);
  } catch (err) {
    outcome.failure = `verify scan failed: ${err instanceof Error ? err.message : String(err)}`;
    return outcome;
  }
  if (outcome.verifyResult.error) {
    outcome.failure = `verify scan failed: ${outcome.verifyResult.error.message}`;
    return outcome;
  }

  // Verified when every triggering finding the plan claimed to fix is gone.
  // Unfixable findings are excluded — the plan never promised those.
  const planResolves = new Set(plan.actions.flatMap((a) => a.resolves));
  const remainingKeys = new Set(outcome.verifyResult.vulnerabilities.map(findingKey));
  outcome.verified = triggeredBy
    .filter((v) => planResolves.has(v.osvId))
    .every((v) => !remainingKeys.has(findingKey(v)));
  if (!outcome.verified) {
    outcome.failure = "verify scan still reports some triggering findings";
  }
  outcome.mttrMs = io.now() - opts.detectedAt;
  return outcome;
}

export interface DaemonWebhookPayload {
  event: "new-findings" | "escalation" | "remediated" | "remediation-failed";
  project: { dir: string; name: string };
  grade: {
    before: { grade: string; score: number };
    after: { grade: string; score: number };
  };
  findings: Array<{
    package: string;
    id: string;
    severity: string;
    knownExploited: boolean;
    epssScore: number | null;
  }>;
  remediation: {
    applied: boolean;
    verified: boolean;
    mttrMs: number | null;
    changes: string[];
  } | null;
  at: string;
}

export function buildWebhookPayload(
  event: DaemonWebhookPayload["event"],
  project: { dir: string; name: string },
  before: { grade: string; score: number },
  after: { grade: string; score: number },
  findings: ScanVulnerability[],
  outcome: RemediationOutcome | null,
  at: string
): DaemonWebhookPayload {
  return {
    event,
    project,
    grade: { before, after },
    findings: findings.map((v) => ({
      package: v.package,
      id: v.osvId,
      severity: v.severity,
      knownExploited: v.knownExploited,
      epssScore: v.epssScore,
    })),
    remediation: outcome
      ? {
          applied: outcome.applied,
          verified: outcome.verified,
          mttrMs: outcome.mttrMs,
          changes: outcome.changes,
        }
      : null,
    at,
  };
}

function timestamp(): string {
  return new Date().toTimeString().slice(0, 8);
}

function formatMttr(ms: number): string {
  return ms < 10_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms / 1000)}s`;
}

interface ProjectRuntime {
  dir: string;
  name: string;
  snapshot: ProjectSnapshot | null;
  scanning: boolean;
  pendingDetectedAt: number | null;
  /** Ignore our own file writes while a remediation is in flight. */
  suppress: boolean;
  failures: number;
  watcher: FSWatcher | null;
  timer: NodeJS.Timeout | null;
  debounce: NodeJS.Timeout | null;
}

export async function daemon(options: DaemonOptions, io: DaemonIO = realIO): Promise<number> {
  const state: DaemonState = await loadState();
  const out = (line: string) => {
    if (!options.json) process.stdout.write(line + "\n");
  };
  const emit = (obj: Record<string, unknown>) => {
    if (options.json) process.stdout.write(JSON.stringify(obj) + "\n");
  };
  const notify = (title: string, body: string, payload: DaemonWebhookPayload) => {
    if (options.desktop) notifyDesktop(title, body);
    if (options.webhook) void sendWebhook(options.webhook, payload);
    emit(payload as unknown as Record<string, unknown>);
  };

  const projects: ProjectRuntime[] = [];
  for (const dir of options.dirs) {
    const abs = resolve(dir);
    projects.push({
      dir: abs,
      name: basename(abs),
      snapshot: state.projects[abs] ?? null,
      scanning: false,
      pendingDetectedAt: null,
      suppress: false,
      failures: 0,
      watcher: null,
      timer: null,
      debounce: null,
    });
  }

  const persist = async (p: ProjectRuntime) => {
    if (!p.snapshot) return;
    state.projects[p.dir] = p.snapshot;
    try {
      await saveState(state);
    } catch (err) {
      out(`  ${yellow("⚠")} could not persist daemon state: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleScan = async (p: ProjectRuntime, detectedAt: number): Promise<void> => {
    if (p.scanning) {
      p.pendingDetectedAt = detectedAt;
      return;
    }
    p.scanning = true;
    try {
      let result: ScanResult;
      try {
        result = await io.scan(p.dir);
        if (result.error) throw new Error(result.error.message);
      } catch (err) {
        p.failures++;
        const message = err instanceof Error ? err.message : String(err);
        out(`  ${gray(timestamp())}  ${bold(p.name)}  ${red("✖")} scan failed: ${message}`);
        emit({ event: "scan-error", project: p.name, message, consecutive: p.failures });
        if (p.failures === FAILURES_BEFORE_ALERT && options.desktop) {
          notifyDesktop("fixly daemon", `${p.name}: ${p.failures} consecutive scan failures — ${message}`);
        }
        return;
      }
      p.failures = 0;
      const grade = computeGrade(result);
      const paint = gradeColor(grade.grade);
      const gradeLabel = paint(bold(`${grade.grade} (${grade.score}/100)`));
      const project = { dir: p.dir, name: p.name };

      if (p.snapshot === null) {
        // First sight of this project ever — report, never auto-fix: starting
        // a watcher must not rewrite files when nothing has changed.
        p.snapshot = snapshotFromScan(result);
        await persist(p);
        const n = result.vulnerabilities.length;
        out(
          `  ${gray(timestamp())}  ${bold(p.name)}  ${gradeLabel} ${dim("·")} baseline: ${n} finding${n === 1 ? "" : "s"} ${dim(`· ${result.totalPackages} pkgs`)}`
        );
        if (n > 0) {
          const plan = buildRemediationPlan(result);
          if (plan.actions.length > 0) {
            out(
              `            ${dim(`existing findings are not auto-fixed — run`)} ${bold(`fixly fix ${p.dir}`)} ${dim(`(forecast ${plan.forecast.after.grade} ${plan.forecast.after.score})`)}`
            );
          }
        }
        emit({ event: "baseline", project: p.name, grade: grade.grade, score: grade.score, findings: result.vulnerabilities.length });
        return;
      }

      const before = p.snapshot.grade;
      const diff = diffAgainstSnapshot(p.snapshot, result);
      const triggered = [...diff.added, ...diff.escalated];

      for (const key of diff.resolvedKeys) {
        out(`            ${green("−")} resolved ${key.replace("::", " — ")}`);
      }

      if (triggered.length === 0) {
        p.snapshot = snapshotFromScan(result);
        await persist(p);
        out(`  ${gray(timestamp())}  ${bold(p.name)}  ${gradeLabel} ${dim("· no change")}`);
        return;
      }

      // ---- something new (or newly exploited) — this is the event ----
      const eventKind = diff.added.length > 0 ? "new-findings" : "escalation";
      out(
        `  ${gray(timestamp())}  ${bold(p.name)}  ${red(bold(`✖ ${triggered.length} ${eventKind === "escalation" ? "escalated" : "new"} finding${triggered.length === 1 ? "" : "s"}`))} ${dim("— grade")} ${gradeColor(before.grade)(bold(`${before.grade} (${before.score})`))} ${dim("→")} ${gradeLabel}`
      );
      for (const v of diff.added) {
        out(`            ${red("+")} ${bold(v.package)}@${v.installedVersion} ${dim("—")} ${v.osvId} (${v.severity})`);
      }
      for (const v of diff.escalated) {
        out(`            ${red("‼")} ${bold(v.package)}@${v.installedVersion} ${dim("—")} ${v.cveId ?? v.osvId} is now known-exploited (CISA KEV)`);
      }

      if (options.notifyOnly) {
        const plan = buildRemediationPlan(result);
        if (plan.actions.length > 0) {
          out(
            `            ${dim("fix ready:")} ${bold(`fixly fix ${p.dir}`)} ${dim(`→ forecast ${plan.forecast.after.grade} (${plan.forecast.after.score})`)}`
          );
        }
        notify(
          `fixly: ${triggered.length} ${eventKind === "escalation" ? "escalated" : "new"} finding${triggered.length === 1 ? "" : "s"} in ${p.name}`,
          `Grade ${before.grade} → ${grade.grade}. Fix ready: fixly fix`,
          buildWebhookPayload(eventKind, project, before, { grade: grade.grade, score: grade.score }, triggered, null, result.scannedAt)
        );
        p.snapshot = snapshotFromScan(result);
        await persist(p);
        return;
      }

      // ---- auto-remediation ----
      out(`            ${yellow("⚡ remediating…")}`);
      p.suppress = true;
      let outcome: RemediationOutcome;
      try {
        outcome = await remediate(p.dir, result, triggered, { noInstall: options.noInstall, detectedAt }, io);
      } finally {
        if (p.debounce) {
          clearTimeout(p.debounce);
          p.debounce = null;
        }
        p.suppress = false;
      }

      const afterResult = outcome.verifyResult ?? result;
      const afterGrade = outcome.verifyResult ? computeGrade(outcome.verifyResult) : grade;
      const after = { grade: afterGrade.grade, score: afterGrade.score };

      if (outcome.verified) {
        const mttr = formatMttr(outcome.mttrMs ?? 0);
        out(
          `            ${green(bold(`✔ remediated in ${mttr}`))} ${dim("— grade")} ${gradeColor(after.grade)(bold(`${after.grade} (${after.score})`))} ${dim("· verified by re-scan")}`
        );
        for (const change of outcome.changes) out(`              ${dim(change)}`);
        if (outcome.plan.unfixable.length > 0) {
          out(
            `              ${gray(`⚠ ${outcome.plan.unfixable.length} finding${outcome.plan.unfixable.length === 1 ? "" : "s"} have no published fix yet (still detected)`)}`
          );
        }
        notify(
          `fixly: remediated ${p.name} in ${mttr}`,
          `Grade ${before.grade} → ${after.grade}, verified by re-scan.`,
          buildWebhookPayload("remediated", project, before, after, triggered, outcome, afterResult.scannedAt)
        );
      } else if (outcome.applied && options.noInstall) {
        out(
          `            ${yellow("◆ package.json fixed")} ${dim(`in ${formatMttr(outcome.mttrMs ?? 0)} — install pending:`)} ${bold("npm install")} ${dim("(--no-install mode, not verified)")}`
        );
        for (const change of outcome.changes) out(`              ${dim(change)}`);
        notify(
          `fixly: ${p.name} manifest fixed — install pending`,
          `Run npm install to realize the fix.`,
          buildWebhookPayload("remediated", project, before, after, triggered, outcome, result.scannedAt)
        );
      } else {
        out(`            ${red(`✖ remediation failed: ${outcome.failure ?? "unknown"}`)}`);
        const plan = outcome.plan;
        if (plan.actions.length > 0) {
          out(`            ${dim("manual fix:")} ${bold(`fixly fix ${p.dir} --write`)}`);
        }
        notify(
          `fixly: could not auto-remediate ${p.name}`,
          outcome.failure ?? "remediation failed",
          buildWebhookPayload("remediation-failed", project, before, after, triggered, outcome, result.scannedAt)
        );
      }

      // Snapshot from the verified state when we have it; otherwise from the
      // detection scan, so unfixable/failed findings become "carried" and
      // don't re-alert every cycle (they still watch for escalation).
      p.snapshot = snapshotFromScan(afterResult);
      await persist(p);
    } finally {
      p.scanning = false;
      if (p.pendingDetectedAt !== null) {
        const at = p.pendingDetectedAt;
        p.pendingDetectedAt = null;
        void handleScan(p, at);
      }
    }
  };

  // ---- startup ----
  const mode = options.notifyOnly
    ? "notify-only"
    : options.noInstall
      ? "auto-fix (manifest only)"
      : "auto-remediate";
  out(
    `\n  ${bold("fixly daemon")} ${dim("—")} ${mode} ${dim(`· advisory re-scan every ${options.intervalMinutes} min · Ctrl+C to stop`)}`
  );
  out("");

  const alive: ProjectRuntime[] = [];
  for (const p of projects) {
    try {
      p.watcher = fsWatch(p.dir, (_event, filename) => {
        if (p.suppress || !filename || !WATCHED_FILES.has(filename.toString())) return;
        const detectedAt = io.now();
        if (p.debounce) clearTimeout(p.debounce);
        p.debounce = setTimeout(() => {
          p.debounce = null;
          void handleScan(p, detectedAt);
        }, DEBOUNCE_MS);
      });
    } catch (err) {
      out(`  ${red("✖")} cannot watch ${p.dir}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    alive.push(p);
    await handleScan(p, io.now());
    // Stagger poll schedules so N projects don't hit OSV simultaneously.
    const offset = alive.length * 3_000;
    p.timer = setTimeout(() => {
      p.timer = setInterval(() => void handleScan(p, io.now()), options.intervalMinutes * 60_000);
      void handleScan(p, io.now());
    }, options.intervalMinutes * 60_000 + offset);
  }

  if (alive.length === 0) {
    process.stderr.write(`${red("✖")} no watchable projects.\n`);
    return 2;
  }

  return new Promise<number>((resolvePromise) => {
    process.once("SIGINT", () => {
      for (const p of alive) {
        p.watcher?.close();
        if (p.timer) clearTimeout(p.timer as NodeJS.Timeout);
        if (p.debounce) clearTimeout(p.debounce);
      }
      out(`\n  ${yellow("daemon stopped")}`);
      resolvePromise(0);
    });
  });
}
