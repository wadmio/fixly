import type { ScanResult } from "@/lib/types";
import Badge from "./Badge";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export default function ReportSummary({ result }: { result: ScanResult }) {
  const counts = SEVERITIES.reduce(
    (acc, s) => {
      acc[s] = result.vulnerabilities.filter((v) => v.severity === s).length;
      return acc;
    },
    {} as Record<string, number>
  );

  const repoLabel = result.repo
    .replace(/^https?:\/\/github\.com\//, "")
    .replace(/\/$/, "");

  const scannedAt = new Date(result.scannedAt).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

  const totalVulns = result.vulnerabilities.length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <svg
            className="h-4 w-4 text-[#BFC3C7]"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.75}
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M2 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H4a2 2 0 01-2-2V7z"
            />
          </svg>
          <h1 className="text-lg font-semibold text-white">{repoLabel}</h1>
        </div>
        <p className="mt-1 text-sm text-[#BFC3C7]">
          {result.totalPackages} packages scanned &middot; {scannedAt} &middot; OSV
        </p>
      </div>

      {/* Severity cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {SEVERITIES.map((sev) => (
          <div
            key={sev}
            className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-4"
          >
            <p className="text-2xl font-semibold text-white">{counts[sev]}</p>
            <div className="mt-1.5">
              <Badge severity={sev} />
            </div>
          </div>
        ))}
      </div>

      {/* Clean state */}
      {totalVulns === 0 && (
        <div className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] px-6 py-10 text-center">
          <svg
            className="mx-auto h-8 w-8 text-emerald-400"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
          <p className="mt-3 text-sm font-medium text-white">No vulnerabilities found</p>
          <p className="mt-1 text-xs text-[#BFC3C7]">
            All {result.totalPackages} packages are clean per OSV.
          </p>
        </div>
      )}
    </div>
  );
}
