"use client";

// Recent scan history (localStorage) on the dashboard: per-repo severity
// totals with a link to re-run each scan. History is device-local by design —
// there is no server-side persistence in this project.

import { useSyncExternalStore } from "react";
import Link from "next/link";
import {
  subscribeHistory,
  getHistorySnapshot,
  getServerHistorySnapshot,
  clearHistory,
  type ScanHistoryEntry,
} from "@/lib/history";

const SEVERITY_TEXT: Array<{ key: keyof ScanHistoryEntry["counts"]; cls: string; label: string }> = [
  { key: "critical", cls: "text-red-400", label: "C" },
  { key: "high", cls: "text-orange-400", label: "H" },
  { key: "medium", cls: "text-yellow-400", label: "M" },
  { key: "low", cls: "text-blue-400", label: "L" },
];

function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function RecentScans() {
  // localStorage as an external store: server render sees an empty history,
  // the client re-reads after writes (recordScan / clearHistory notify).
  const entries = useSyncExternalStore(
    subscribeHistory,
    getHistorySnapshot,
    getServerHistorySnapshot
  );

  // Nothing scanned on this device — render nothing.
  if (entries.length === 0) return null;

  return (
    <div className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-5">
      <div className="mb-3 flex items-center justify-between">
        <p className="text-xs font-medium text-white">Recent scans on this device</p>
        <button
          type="button"
          onClick={clearHistory}
          className="text-[11px] text-[#BFC3C7]/50 hover:text-[#BFC3C7] transition-colors"
        >
          Clear history
        </button>
      </div>

      <ul className="divide-y divide-[#D1D5DB]/10">
        {entries.slice(0, 8).map((e) => (
          <li key={`${e.repo}-${e.scannedAt}`}>
            <Link
              href={e.url}
              className="group flex items-center justify-between gap-3 py-2.5"
            >
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-white group-hover:text-[#BFC3C7] transition-colors">
                  {e.repo}
                </p>
                <p className="mt-0.5 text-[11px] text-[#BFC3C7]/60">
                  {timeAgo(e.scannedAt)} · {e.totalPackages} packages
                  {e.transitivePackages > 0 ? ` (${e.transitivePackages} transitive)` : ""}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2.5 font-mono text-[11px]">
                {e.totalFindings === 0 ? (
                  <span className="text-emerald-400">clean</span>
                ) : (
                  SEVERITY_TEXT.filter(({ key }) => e.counts[key] > 0).map(({ key, cls, label }) => (
                    <span key={key} className={cls}>
                      {e.counts[key]}
                      {label}
                    </span>
                  ))
                )}
              </div>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
