// Finding-level verification — after an external package-lock.json change
// (npm install ran outside Fixly), the watcher's rescan is compared to the
// previous scan and every finding is classified. Pure and vscode-free, like
// advice.ts. This is deliberately FINDING-level, not action-level: advice-only
// means any external change is verifiable, whoever made it and however they
// chose to fix it.

import { compareFindingKeys, findingKey } from "@fixly/core/compare";
import type { ScanResult } from "@fixly/core";

export type FindingOutcome =
  | "VERIFIED_RESOLVED"
  | "STILL_PRESENT"
  | "NEW_FINDING_INTRODUCED";

export interface VerificationSummary {
  resolved: number;
  stillPresent: number;
  introduced: number;
  /** One line per finding: "VERIFIED_RESOLVED: minimist GHSA-xxxx" — worst
   *  outcomes first (introduced, then resolved, then still-present). */
  lines: string[];
  /** The one-line toast/log summary. */
  message: string;
}

/** "package::osvId" → "package osvId" for display. */
function display(key: string): string {
  return key.replace("::", " ");
}

/**
 * Whether a completed rescan should be verified against the previous scan:
 * only lock-file-triggered rescans (the ones that follow an npm install), only
 * when a previous scan exists to compare against, and never when either scan
 * carries an error (a partial result would fake "resolved" findings).
 */
export function shouldVerify(
  lockChanged: boolean | undefined,
  previous: ScanResult | undefined,
  next: ScanResult
): previous is ScanResult {
  return Boolean(lockChanged) && previous !== undefined && !previous.error && !next.error;
}

/**
 * Classify every finding across the two scans by identity (package + advisory)
 * and produce the concise summary shown once per verified rescan.
 */
export function verifyFindings(
  previous: ScanResult,
  next: ScanResult
): VerificationSummary {
  const delta = compareFindingKeys(
    previous.vulnerabilities.map(findingKey),
    next.vulnerabilities.map(findingKey)
  );

  const lines: string[] = [
    ...delta.added.map((k) => `NEW_FINDING_INTRODUCED: ${display(k)}`),
    ...delta.resolved.map((k) => `VERIFIED_RESOLVED: ${display(k)}`),
    ...delta.unchanged.map((k) => `STILL_PRESENT: ${display(k)}`),
  ];

  const parts: string[] = [
    `${delta.resolved.length} resolved`,
    `${delta.unchanged.length} still present`,
    `${delta.added.length} new ${delta.added.length === 1 ? "finding" : "findings"} introduced`,
  ];

  return {
    resolved: delta.resolved.length,
    stillPresent: delta.unchanged.length,
    introduced: delta.added.length,
    lines,
    message: `Fixly verification: ${parts.join(", ")}.`,
  };
}
