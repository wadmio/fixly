// Terminal presentation — zero-dependency ANSI styling that respects NO_COLOR
// and non-TTY pipes (CI logs stay clean).

import type { Severity } from "@fixly/core";
import type { Grade, VerdictLevel } from "@fixly/core";

const colorEnabled =
  process.env.NO_COLOR === undefined &&
  process.env.FORCE_COLOR !== "0" &&
  (process.stdout.isTTY || process.env.FORCE_COLOR !== undefined);

function style(open: number, close: number): (s: string) => string {
  return (s) => (colorEnabled ? `[${open}m${s}[${close}m` : s);
}

export const bold = style(1, 22);
export const dim = style(2, 22);
export const red = style(31, 39);
export const green = style(32, 39);
export const yellow = style(33, 39);
export const blue = style(34, 39);
export const magenta = style(35, 39);
export const cyan = style(36, 39);
export const gray = style(90, 39);

export function severityLabel(severity: Severity): string {
  const tag = severity.toUpperCase().padEnd(8);
  switch (severity) {
    case "critical":
      return red(bold(tag));
    case "high":
      return red(tag);
    case "medium":
      return yellow(tag);
    case "low":
      return blue(tag);
    default:
      return gray(tag);
  }
}

export function gradeColor(grade: Grade): (s: string) => string {
  switch (grade) {
    case "A":
      return green;
    case "B":
      return cyan;
    case "C":
      return yellow;
    case "D":
      return magenta;
    default:
      return red;
  }
}

export function verdictBanner(verdict: VerdictLevel): string {
  switch (verdict) {
    case "safe":
      return green(bold("✔ SAFE"));
    case "caution":
      return yellow(bold("⚠ CAUTION"));
    case "unknown":
      return gray(bold("? UNVERIFIED"));
    case "block":
      return red(bold("✖ BLOCK"));
  }
}

/** Render the vibecheck grade box, e.g. ╭───╮ │ B │ ╰───╯ with the score. */
export function gradeBox(grade: Grade, score: number): string {
  const paint = gradeColor(grade);
  const letter = paint(bold(` ${grade} `));
  return [
    `  ${paint("╭───╮")}`,
    `  ${paint("│")}${letter}${paint("│")}  ${bold(`${score}/100`)} ${dim("· Fixly Score")}`,
    `  ${paint("╰───╯")}`,
  ].join("\n");
}
