"use client";

// Findings table. Client component only for the direct/transitive filter —
// all data arrives fully computed from the server scan.

import { useMemo, useState } from "react";
import type { ScanVulnerability } from "@fixly/core";
import { Badge } from "@fixly/ui";

type DepFilter = "all" | "direct" | "transitive";

const FILTERS: Array<{ id: DepFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "direct", label: "Direct" },
  { id: "transitive", label: "Transitive" },
];

export default function ScanResultsTable({
  vulnerabilities,
}: {
  vulnerabilities: ScanVulnerability[];
}) {
  const [filter, setFilter] = useState<DepFilter>("all");

  const transitiveCount = useMemo(
    () => vulnerabilities.filter((v) => v.dependencyType === "transitive").length,
    [vulnerabilities]
  );

  const visible = useMemo(() => {
    if (filter === "all") return vulnerabilities;
    if (filter === "transitive") {
      return vulnerabilities.filter((v) => v.dependencyType === "transitive");
    }
    return vulnerabilities.filter((v) => v.dependencyType !== "transitive");
  }, [vulnerabilities, filter]);

  if (vulnerabilities.length === 0) return null;

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-white">
          {vulnerabilities.length}{" "}
          {vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities"} found
          {transitiveCount > 0 && (
            <span className="ml-1.5 font-normal text-[#BFC3C7]/60">
              ({vulnerabilities.length - transitiveCount} direct, {transitiveCount} transitive)
            </span>
          )}
        </h2>

        {transitiveCount > 0 && (
          <div className="flex gap-1 rounded-lg border border-[#D1D5DB]/10 bg-[#1A1A1A] p-0.5">
            {FILTERS.map(({ id, label }) => (
              <button
                key={id}
                type="button"
                onClick={() => setFilter(id)}
                className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  filter === id
                    ? "bg-white text-[#0A0A0A]"
                    : "text-[#BFC3C7] hover:text-white"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="overflow-x-auto rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#D1D5DB]/10 text-left text-xs font-medium text-[#BFC3C7]">
              <th className="px-4 py-3">Package</th>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Summary</th>
              <th className="px-4 py-3">Fix</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#D1D5DB]/10">
            {visible.map((vuln, i) => (
              <tr
                key={`${vuln.osvId}-${vuln.package}-${vuln.installedVersion}-${i}`}
                className="hover:bg-[#0A0A0A] transition-colors align-top"
              >
                {/* Package */}
                <td className="px-4 py-3.5">
                  <div className="flex items-center gap-1.5">
                    <p className="font-medium text-white">{vuln.package}</p>
                    {vuln.dependencyType === "transitive" && (
                      <span
                        className="rounded border border-[#D1D5DB]/20 px-1 py-px text-[10px] text-[#BFC3C7]/70"
                        title="Not declared in package.json — pulled in by another dependency (found in the lock file tree)."
                      >
                        transitive
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 font-mono text-xs text-[#BFC3C7]">
                    v{vuln.installedVersion}
                    {vuln.versionSource === "range-minimum" && (
                      <span
                        className="ml-1 text-[#BFC3C7]/50"
                        title="No lockfile — checked the minimum of the declared range. Approximate."
                      >
                        (≈ approx)
                      </span>
                    )}
                  </p>
                  {vuln.affectedRanges.length > 0 && (
                    <p className="mt-0.5 font-mono text-[10px] text-[#BFC3C7]/45">
                      affects {vuln.affectedRanges.join(", ")}
                    </p>
                  )}
                </td>

                {/* Vuln ID */}
                <td className="px-4 py-3.5">
                  {vuln.references[0] ? (
                    <a
                      href={vuln.references[0]}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-xs text-[#BFC3C7] hover:text-white transition-colors"
                    >
                      {vuln.osvId}
                    </a>
                  ) : (
                    <span className="font-mono text-xs text-[#BFC3C7]">{vuln.osvId}</span>
                  )}
                  {vuln.cveId && (
                    <p className="mt-0.5 font-mono text-xs text-[#BFC3C7]/50">
                      {vuln.cveId}
                    </p>
                  )}
                  <p
                    className="mt-0.5 text-[10px] uppercase tracking-wide text-[#BFC3C7]/40"
                    title={
                      vuln.sources.includes("nvd")
                        ? "Reported by OSV and cross-referenced against the National Vulnerability Database."
                        : "Reported by the OSV database."
                    }
                  >
                    {vuln.sources.join(" · ")}
                  </p>
                </td>

                {/* Severity */}
                <td className="px-4 py-3.5">
                  <Badge severity={vuln.severity} />
                  {vuln.cvssScore !== null && (
                    <p className="mt-0.5 font-mono text-xs text-[#BFC3C7]/60">
                      {vuln.cvssScore.toFixed(1)}
                    </p>
                  )}
                  {vuln.nvd?.cvssScore != null && (
                    <p
                      className="mt-0.5 font-mono text-[10px] text-[#BFC3C7]/45"
                      title={`NVD independently scores this CVE ${vuln.nvd.cvssScore.toFixed(1)}${vuln.nvd.severity ? ` (${vuln.nvd.severity})` : ""}.`}
                    >
                      NVD {vuln.nvd.cvssScore.toFixed(1)}
                    </p>
                  )}
                </td>

                {/* Summary */}
                <td className="px-4 py-3.5 max-w-sm">
                  <p className="text-sm text-[#BFC3C7] leading-snug line-clamp-3">
                    {vuln.title}
                  </p>
                </td>

                {/* Fix */}
                <td className="px-4 py-3.5 whitespace-nowrap">
                  {vuln.fixedVersion ? (
                    <span className="font-mono text-xs text-emerald-400">
                      → {vuln.fixedVersion}
                    </span>
                  ) : (
                    <span className="text-xs text-[#BFC3C7]/30">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {visible.length === 0 && (
          <p className="px-4 py-6 text-center text-xs text-[#BFC3C7]/60">
            No {filter} findings — switch the filter to see the rest.
          </p>
        )}
      </div>
    </div>
  );
}
