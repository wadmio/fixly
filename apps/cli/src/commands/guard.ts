// `fixly guard -- npm install <pkgs>` — the install firewall. Every package
// on the command line is verdict-checked BEFORE the real package manager
// runs: BLOCK aborts, CAUTION asks (or requires --yes in CI), SAFE passes
// through untouched. The wrapped command runs with inherited stdio, so the
// experience is exactly `npm install` — with a seatbelt.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { checkPackage, type PackageVerdict } from "@fixly/core";
import { parsePackageSpec } from "./check";
import { bold, dim, gray, green, red, yellow, verdictBanner } from "../ui";

const PACKAGE_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun"]);
const INSTALL_SUBCOMMANDS = new Set(["install", "i", "add"]);

export interface ParsedInstall {
  /** The package manager binary. */
  command: string;
  /** Full argv to pass through. */
  args: string[];
  /** Package specs named on the command line (empty for a bare lockfile install). */
  specs: string[];
  /** Specs we cannot check (git/file/url/workspace references). */
  uncheckable: string[];
}

/** True when the spec is a registry package (not git/file/url/workspace). */
function isRegistrySpec(spec: string): boolean {
  return !/^(\.|\/|~|file:|git\+|git:|github:|https?:|workspace:)/.test(spec);
}

/** A version is checkable when it's exact; ranges/tags resolve to "latest". */
function checkableVersion(version: string | null): string | null {
  if (!version) return null;
  return /^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version) ? version : null;
}

/**
 * Parse a wrapped install command. Returns null when it isn't a recognized
 * `<npm|pnpm|yarn|bun> <install|i|add> …` invocation.
 */
export function parseInstallCommand(argv: string[]): ParsedInstall | null {
  if (argv.length === 0) return null;
  const command = argv[0];
  if (!PACKAGE_MANAGERS.has(command)) return null;
  const sub = argv[1];
  if (!sub || !INSTALL_SUBCOMMANDS.has(sub)) return null;

  const specs: string[] = [];
  const uncheckable: string[] = [];
  for (const arg of argv.slice(2)) {
    if (arg.startsWith("-")) continue; // flags pass through
    if (isRegistrySpec(arg)) specs.push(arg);
    else uncheckable.push(arg);
  }
  return { command, args: argv.slice(1), specs, uncheckable };
}

function verdictLine(v: PackageVerdict): string {
  const label = `${bold(v.package)}${v.evaluatedVersion ? dim(`@${v.evaluatedVersion}`) : ""}`;
  const reason = v.reasons[0] ? ` ${dim("—")} ${v.reasons[0]}` : "";
  return `  ${verdictBanner(v.verdict)}  ${label}${reason}`;
}

function runPassthrough(command: string, args: string[]): Promise<number> {
  // npm/pnpm/yarn are .cmd shims on Windows, which require a shell. Passing an
  // args array alongside shell:true is deprecated (DEP0190), so build one
  // quoted command line; on POSIX, spawn the binary directly with the array.
  const windows = process.platform === "win32";
  const quote = (a: string) => (/[\s"^&|<>()%!]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a);
  return new Promise((resolvePromise) => {
    const child = windows
      ? spawn([command, ...args].map(quote).join(" "), { stdio: "inherit", shell: true })
      : spawn(command, args, { stdio: "inherit" });
    child.on("close", (code) => resolvePromise(code ?? 1));
    child.on("error", (err) => {
      process.stderr.write(`${red("✖")} could not run ${command}: ${err.message}\n`);
      resolvePromise(2);
    });
  });
}

async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(question)).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

export interface GuardOptions {
  /** Everything after `fixly guard [--] `. */
  argv: string[];
  /** Auto-accept CAUTION verdicts (CI mode). */
  yes: boolean;
  /** Override BLOCK verdicts. Loud. */
  force: boolean;
}

export async function guard(options: GuardOptions): Promise<number> {
  const parsed = parseInstallCommand(options.argv);
  if (!parsed) {
    process.stderr.write(
      `${red("✖")} usage: fixly guard -- <npm|pnpm|yarn|bun> <install|add> [packages]\n`
    );
    return 2;
  }

  if (parsed.specs.length === 0) {
    // Bare lockfile install — nothing named to pre-check. Pass through and
    // point at the post-install habit.
    process.stderr.write(
      `${dim("fixly guard: no packages named — passing through. Run `fixly vibecheck` after lockfile installs.")}\n`
    );
    return runPassthrough(parsed.command, parsed.args);
  }

  process.stderr.write(`\n${bold("fixly guard")} ${dim("— pre-install check")}\n\n`);
  for (const skipped of parsed.uncheckable) {
    process.stderr.write(`  ${gray(`? cannot check ${skipped} (not a registry package)`)}\n`);
  }

  const verdicts = await Promise.all(
    parsed.specs.map((spec) => {
      const { name, version } = parsePackageSpec(spec);
      return checkPackage(name, checkableVersion(version));
    })
  );

  for (const v of verdicts) process.stderr.write(verdictLine(v) + "\n");
  process.stderr.write("\n");

  const blocked = verdicts.filter((v) => v.verdict === "block");
  const cautioned = verdicts.filter((v) => v.verdict === "caution");

  if (blocked.length > 0 && !options.force) {
    process.stderr.write(
      `${red(bold("✖ install blocked"))} — ${blocked.map((v) => v.package).join(", ")} ${blocked.length === 1 ? "is" : "are"} not safe to install.\n`
    );
    const didYouMean = blocked.map((v) => v.signals.typosquatOf).filter(Boolean);
    if (didYouMean.length > 0) {
      process.stderr.write(`  ${yellow("did you mean:")} ${didYouMean.join(", ")}\n`);
    }
    process.stderr.write(`  ${dim("(--force overrides; you own the consequences)")}\n`);
    return 2;
  }
  if (blocked.length > 0 && options.force) {
    process.stderr.write(`${red(bold("⚠ BLOCK overridden with --force."))}\n`);
  }

  if (cautioned.length > 0 && !options.yes && blocked.length === 0) {
    if (!process.stdin.isTTY) {
      process.stderr.write(
        `${yellow("⚠ caution verdicts in a non-interactive session")} — re-run with --yes to proceed.\n`
      );
      return 1;
    }
    const ok = await confirm(`  ${yellow("proceed anyway?")} ${dim("[y/N]")} `);
    if (!ok) {
      process.stderr.write(`${dim("aborted.")}\n`);
      return 1;
    }
  }

  process.stderr.write(`${green("→")} ${parsed.command} ${parsed.args.join(" ")}\n\n`);
  return runPassthrough(parsed.command, parsed.args);
}
