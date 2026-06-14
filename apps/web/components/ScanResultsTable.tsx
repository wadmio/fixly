import type { ScanVulnerability } from "@fixly/core";
import { Badge } from "@fixly/ui";

export default function ScanResultsTable({
  vulnerabilities,
}: {
  vulnerabilities: ScanVulnerability[];
}) {
  if (vulnerabilities.length === 0) return null;

  return (
    <div>
      <h2 className="mb-3 text-sm font-semibold text-white">
        {vulnerabilities.length}{" "}
        {vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities"} found
      </h2>

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
            {vulnerabilities.map((vuln, i) => (
              <tr
                key={`${vuln.osvId}-${i}`}
                className="hover:bg-[#0A0A0A] transition-colors align-top"
              >
                {/* Package */}
                <td className="px-4 py-3.5">
                  <p className="font-medium text-white">{vuln.package}</p>
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
                </td>

                {/* Severity */}
                <td className="px-4 py-3.5">
                  <Badge severity={vuln.severity} />
                  {vuln.cvssScore !== null && (
                    <p className="mt-0.5 font-mono text-xs text-[#BFC3C7]/60">
                      {vuln.cvssScore.toFixed(1)}
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
      </div>
    </div>
  );
}
