"use client";

// Records a completed scan into local history and shows the scan-over-scan
// delta ("2 new, 1 resolved since last scan"). Client component because
// history lives in localStorage — the report itself stays server-rendered.

import { useEffect, useState } from "react";
import type { ScanDelta } from "@fixly/core/compare";
import { recordScan, type ScanHistoryEntry } from "@/lib/history";

export default function ScanHistoryRecorder({ entry }: { entry: ScanHistoryEntry }) {
  const [outcome, setOutcome] = useState<{
    delta: ScanDelta | null;
    previousScannedAt: string | null;
  } | null>(null);

  useEffect(() => {
    // Record after paint: keeps the server-rendered report's first paint
    // clean and satisfies react-hooks/set-state-in-effect. recordScan is
    // idempotent per (repo, scannedAt), so strict-mode double effects and
    // cancelled timers can't duplicate history entries.
    const timer = setTimeout(() => {
      const { previous, delta } = recordScan(entry);
      setOutcome({ delta, previousScannedAt: previous?.scannedAt ?? null });
    }, 0);
    return () => clearTimeout(timer);
  }, [entry]);

  // Nothing to compare against — first scan of this repo on this browser.
  if (!outcome?.delta || !outcome.previousScannedAt) return null;

  const { added, resolved, unchanged } = outcome.delta;
  const prevDate = new Date(outcome.previousScannedAt).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

  if (added.length === 0 && resolved.length === 0) {
    return (
      <div className="panel px-5 py-3">
        <p className="text-xs text-[#9DA2A8]">
          No change since the last scan ({prevDate}) — {unchanged.length}{" "}
          {unchanged.length === 1 ? "finding" : "findings"} unchanged.
        </p>
      </div>
    );
  }

  return (
    <div
      className={`rounded-xl border px-5 py-4 ${
        added.length > 0
          ? "border-red-400/20 bg-red-400/[0.06]"
          : "border-emerald-400/20 bg-emerald-400/[0.06]"
      }`}
    >
      <p className="text-xs font-medium text-white">Since the last scan ({prevDate})</p>
      <div className="mt-1.5 flex flex-wrap gap-x-5 gap-y-1">
        {added.length > 0 && (
          <span className="text-xs text-red-400">
            +{added.length} new {added.length === 1 ? "finding" : "findings"}
          </span>
        )}
        {resolved.length > 0 && (
          <span className="text-xs text-emerald-400">
            −{resolved.length} resolved
          </span>
        )}
        <span className="text-xs text-[#BFC3C7]/70">{unchanged.length} unchanged</span>
      </div>
      {added.length > 0 && (
        <ul className="mt-2 space-y-0.5">
          {added.slice(0, 5).map((key) => (
            <li key={key} className="font-mono text-[11px] text-red-300/80">
              {key.replace("::", " — ")}
            </li>
          ))}
          {added.length > 5 && (
            <li className="text-[11px] text-[#BFC3C7]/60">…and {added.length - 5} more</li>
          )}
        </ul>
      )}
    </div>
  );
}
