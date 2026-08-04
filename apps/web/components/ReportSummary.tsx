import type { ScanResult, Severity } from "@fixly/core";
import { SEVERITY_HEX } from "@/lib/grade";

// All five severities — `unknown` counts too (a finding with no CVSS vector
// and no database severity is still a finding).
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export default function ReportSummary({ result }: { result: ScanResult }) {
  const counts = SEVERITIES.reduce(
    (acc, s) => {
      acc[s] = result.vulnerabilities.filter((v) => v.severity === s).length;
      return acc;
    },
    {} as Record<Severity, number>
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
  const present = SEVERITIES.filter((s) => counts[s] > 0);

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
            aria-hidden="true"
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
          {result.totalPackages}{" "}
          {result.totalPackages === 1 ? "package" : "packages"}
          {result.transitivePackages > 0 ? (
            <>
              {" "}
              <span className="text-[#BFC3C7]/60">
                ({result.directPackages} direct + {result.transitivePackages} transitive)
              </span>
            </>
          ) : null}{" "}
          &middot; {result.resolvedPackages} checked
          {result.target.branch ? (
            <>
              {" "}
              &middot; branch{" "}
              <span className="font-mono text-xs">{result.target.branch}</span>
            </>
          ) : null}{" "}
          &middot; {scannedAt} &middot;{" "}
          <span title={result.source === "osv+nvd" ? "Findings cross-referenced against the National Vulnerability Database" : "OSV database"}>
            {result.source === "osv+nvd" ? "OSV + NVD" : "OSV"}
          </span>
        </p>
        {(result.target.filesFound.length > 0 || result.target.subpath) && (
          <p className="mt-1 text-xs text-[#BFC3C7]/60">
            {result.target.subpath ? (
              <>
                path{" "}
                <span className="font-mono">{result.target.subpath}</span>
                {" · "}
              </>
            ) : null}
            files found: {result.target.filesFound.join(", ") || "none"}
            {result.target.filesMissing.length > 0
              ? ` · missing: ${result.target.filesMissing.join(", ")}`
              : ""}
          </p>
        )}
      </div>

      {/* Overview: packages · findings · severity distribution */}
      <div className="panel grid grid-cols-1 gap-6 p-6 sm:grid-cols-[1fr_1fr_2.2fr] sm:gap-8">
        <div>
          <p className="text-[26px] font-semibold tabular-nums leading-none tracking-tight text-white">
            {result.totalPackages}
          </p>
          <p className="microlabel mt-2">Packages</p>
          <p className="mt-1 text-[11px] text-[#6E7378]">
            {result.directPackages} direct · {result.transitivePackages} transitive
          </p>
        </div>
        <div>
          <p
            className={`text-[26px] font-semibold tabular-nums leading-none tracking-tight ${totalVulns > 0 ? "text-red-400" : "text-emerald-400"}`}
          >
            {totalVulns}
          </p>
          <p className="microlabel mt-2">Findings</p>
          <p className="mt-1 text-[11px] text-[#6E7378]">
            {result.resolvedPackages} packages checked
          </p>
        </div>
        <div>
          <p className="microlabel mb-2.5">Severity distribution</p>
          <div className="flex h-2 gap-0.5 overflow-hidden rounded bg-white/5" aria-hidden="true">
            {totalVulns > 0 ? (
              present.map((s) => (
                <span
                  key={s}
                  className="block min-w-2 rounded-sm"
                  style={{ flex: counts[s], background: SEVERITY_HEX[s] }}
                  title={`${counts[s]} ${s}`}
                />
              ))
            ) : (
              <span className="block flex-1 rounded-sm" style={{ background: "rgba(52,211,153,0.4)" }} />
            )}
          </div>
          <div className="mt-2.5 flex flex-wrap gap-x-3.5 gap-y-1">
            {present.length > 0 ? (
              present.map((s) => (
                <span key={s} className="inline-flex items-center gap-1.5 text-[11.5px] capitalize text-[#9DA2A8]">
                  <span
                    className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
                    style={{ background: SEVERITY_HEX[s] }}
                    aria-hidden="true"
                  />
                  {counts[s]} {s}
                </span>
              ))
            ) : (
              <span className="text-[11px] text-[#BFC3C7]/60">no findings</span>
            )}
          </div>
        </div>
      </div>

      {/* Clean state */}
      {totalVulns === 0 && (
        <div className="panel px-6 py-10 text-center">
          <svg
            className="mx-auto h-8 w-8 text-emerald-400"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            />
          </svg>
          <p className="mt-3 text-sm font-medium text-white">No vulnerabilities found</p>
          <p className="mt-1 text-xs text-[#BFC3C7]">
            All {result.resolvedPackages} checked packages are clean per OSV.
          </p>
        </div>
      )}
    </div>
  );
}
