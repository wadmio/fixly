// The "Fixly Guardian" terminal — a read-only pseudoterminal that streams the
// guardian's event log into the terminal panel, next to where installs happen.
// npm prints its noise; Fixly answers with one aligned, timestamped line per
// event. Lines fired before the terminal is opened are buffered and replayed.

import * as vscode from "vscode";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const GRAY = "\x1b[90m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";

export type GuardianLineKind =
  | "baseline"
  | "detected"
  | "escalated"
  | "remediating"
  | "remediated"
  | "resolved"
  | "failed"
  | "info";

const KIND_STYLE: Record<GuardianLineKind, { label: string; color: string }> = {
  baseline: { label: "baseline", color: GRAY },
  detected: { label: "detected", color: RED },
  escalated: { label: "escalated", color: RED },
  remediating: { label: "remediating", color: YELLOW },
  remediated: { label: "remediated", color: GREEN },
  resolved: { label: "resolved", color: GREEN },
  failed: { label: "failed", color: RED },
  info: { label: "", color: GRAY },
};

export class GuardianTerminal {
  private readonly writeEmitter = new vscode.EventEmitter<string>();
  private terminal: vscode.Terminal | undefined;
  private opened = false;
  private buffer: string[] = [];

  /** Create the terminal tab (idempotent). */
  ensure(): void {
    if (this.terminal) return;
    const pty: vscode.Pseudoterminal = {
      onDidWrite: this.writeEmitter.event,
      open: () => {
        this.opened = true;
        for (const line of this.buffer) this.writeEmitter.fire(line);
        this.buffer = [];
      },
      close: () => {
        this.terminal = undefined;
        this.opened = false;
      },
      handleInput: () => {
        // read-only — the guardian reports here, it does not take orders
      },
    };
    this.terminal = vscode.window.createTerminal({ name: "Fixly Guardian", pty });
  }

  /** Reveal the terminal without stealing keyboard focus. */
  show(): void {
    this.ensure();
    this.terminal?.show(true);
  }

  write(kind: GuardianLineKind, text: string): void {
    this.ensure();
    const at = new Date().toTimeString().slice(0, 8);
    const style = KIND_STYLE[kind];
    const label = style.label ? `${style.color}${style.label.padEnd(12)}${RESET}` : "".padEnd(12);
    const line = `${GREEN}${BOLD}fixly${RESET}  ${GRAY}${at}${RESET}  ${label}${text}\r\n`;
    if (this.opened) this.writeEmitter.fire(line);
    else this.buffer.push(line);
  }

  dispose(): void {
    this.terminal?.dispose();
    this.writeEmitter.dispose();
  }
}
