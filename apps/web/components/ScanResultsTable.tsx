"use client";

// Findings table. Client component only for the filters — all data arrives
// fully computed from the server scan. Exploit-intel is shown as bordered
// chips (Malware / KEV / PoC / EPSS), the same treatment as the VS Code
// extension's report.

import { useMemo, useState } from "react";
import type { ScanVulnerability, Severity } from "@fixly/core";
import { isNewlyExploited, kevAgeDays } from "@fixly/core/kev";
import { Badge } from "@fixly/ui";

type DepFilter = "all" | "direct" | "transitive";
type SevFilter = "all" | Severity;

const DEP_FILTERS: Array<{ id: DepFilter; label: string }> = [
  { id: "all", label: "All" },
  { id: "direct", label: "Direct" },
  { id: "transitive", label: "Transitive" },
];

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"];

function IntelChips({ vuln }: { vuln: ScanVulnerability }) {
  const chips: Array<{ key: string; text: string; cls: string; title: string }> = [];
  if (vuln.malicious) {
    chips.push({
      key: "mal",
      text: "Malware",
      cls: "border-red-800 bg-red-950/60 text-red-400",
      title: "OSV flags this package itself as malware — remove it; there is nothing to 'upgrade'.",
    });
  }
  if (vuln.knownExploited) {
    const age = kevAgeDays(vuln.kevDateAdded);
    chips.push({
      key: "kev",
      text: isNewlyExploited(vuln.kevDateAdded) ? "KEV · new" : "KEV",
      cls: "border-red-800/60 bg-red-950/40 text-red-400",
      title: `Known Exploited Vulnerabilities catalog — confirmed exploitation in the wild. Top remediation priority.${age !== null ? ` Added ${age} days ago.` : ""}`,
    });
  }
  if (vuln.pocCount !== null && vuln.pocCount > 0) {
    chips.push({
      key: "poc",
      text: `PoC ×${vuln.pocCount}`,
      cls: "border-orange-800/60 bg-orange-950/30 text-orange-400",
      title: `${vuln.pocCount} public proof-of-concept exploit repo(s) for this CVE on GitHub — exploit code is publicly available.`,
    });
  }
  if (vuln.epssScore !== null && vuln.epssScore >= 0.1) {
    chips.push({
      key: "epss",
      text: `EPSS ${(vuln.epssScore * 100).toFixed(0)}%`,
      cls: "border-[#D1D5DB]/20 text-[#BFC3C7]/80",
      title: `EPSS predicts a ${(vuln.epssScore * 100).toFixed(0)}% probability this CVE is exploited within 30 days.`,
    });
  }
  if (chips.length === 0) return null;
  return (
    <span className="mt-1.5 flex flex-wrap gap-1">
      {chips.map((c) => (
        <span
          key={c.key}
          className={`rounded border px-1.5 py-px text-[10px] font-medium whitespace-nowrap ${c.cls}`}
          title={c.title}
        >
          {c.text}
        </span>
      ))}
    </span>
  );
}

export default function ScanResultsTable({
  vulnerabilities,
}: {
  vulnerabilities: ScanVulnerability[];
}) {
  const [depFilter, setDepFilter] = useState<DepFilter>("all");
  const [sevFilter, setSevFilter] = useState<SevFilter>("all");

  const transitiveCount = useMemo(
    () => vulnerabilities.filter((v) => v.dependencyType === "transitive").length,
    [vulnerabilities]
  );

  const presentSeverities = useMemo(
    () => SEVERITY_ORDER.filter((s) => vulnerabilities.some((v) => v.severity === s)),
    [vulnerabilities]
  );

  const visible = useMemo(() => {
    let rows = vulnerabilities;
    if (depFilter === "transitive") rows = rows.filter((v) => v.dependencyType === "transitive");
    else if (depFilter === "direct") rows = rows.filter((v) => v.dependencyType !== "transitive");
    if (sevFilter !== "all") rows = rows.filter((v) => v.severity === sevFilter);
    return rows;
  }, [vulnerabilities, depFilter, sevFilter]);

  if (vulnerabilities.length === 0) return null;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-white">
          {vulnerabilities.length}{" "}
          {vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities"} found
          {transitiveCount > 0 && (
            <span className="ml-1.5 font-normal text-[#BFC3C7]/60">
              ({vulnerabilities.length - transitiveCount} direct, {transitiveCount} transitive)
            </span>
          )}
        </h2>

        <div className="flex flex-wrap items-center gap-2">
          {presentSeverities.length > 1 && (
            <div className="flex gap-1 rounded-lg border border-white/[0.07] bg-[#111214] p-0.5" role="group" aria-label="Filter by severity">
              <button
                type="button"
                onClick={() => setSevFilter("all")}
                aria-pressed={sevFilter === "all"}
                className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                  sevFilter === "all" ? "bg-white text-[#0A0A0A]" : "text-[#BFC3C7] hover:text-white"
                }`}
              >
                All
              </button>
              {presentSeverities.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSevFilter(sevFilter === s ? "all" : s)}
                  aria-pressed={sevFilter === s}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium capitalize transition-colors ${
                    sevFilter === s ? "bg-white text-[#0A0A0A]" : "text-[#BFC3C7] hover:text-white"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          )}

          {transitiveCount > 0 && (
            <div className="flex gap-1 rounded-lg border border-white/[0.07] bg-[#111214] p-0.5" role="group" aria-label="Filter by dependency type">
              {DEP_FILTERS.map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setDepFilter(id)}
                  aria-pressed={depFilter === id}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    depFilter === id
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
      </div>

      <div className="panel overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.07] text-left text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[#8B8F94]">
              <th scope="col" className="px-4 py-3">Package</th>
              <th scope="col" className="px-4 py-3">ID</th>
              <th scope="col" className="px-4 py-3">Severity</th>
              <th scope="col" className="px-4 py-3">Summary</th>
              <th scope="col" className="px-4 py-3">Fix</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.05]">
            {visible.map((vuln, i) => (
              <tr
                key={`${vuln.osvId}-${vuln.package}-${vuln.installedVersion}-${i}`}
                className="hover:bg-white/[0.02] transition-colors align-top"
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

                {/* Severity + intel */}
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
                  <IntelChips vuln={vuln} />
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
            No findings match the current filters — reset them to see the rest.
          </p>
        )}
      </div>
    </div>
  );
}
