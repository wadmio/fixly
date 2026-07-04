import Link from "next/link";
import { runScan, scanProjectFiles, findingKey, countBySeverity, type ScanResult } from "@fixly/core";
import ReportSummary from "@/components/ReportSummary";
import ScanResultsTable from "@/components/ScanResultsTable";
import ScanForm from "@/components/ScanForm";
import ScanHistoryRecorder from "@/components/ScanHistoryRecorder";
import { getFixture } from "@/lib/fixtures";
import type { ScanHistoryEntry } from "@/lib/history";

// Compact, serializable summary handed to the client-side history recorder.
function historyEntry(result: ScanResult, repo: string, fixture: string): ScanHistoryEntry {
  return {
    repo: result.repo.replace(/^https?:\/\/github\.com\//, "").replace(/\/$/, ""),
    url: fixture
      ? `/dashboard/results?fixture=${encodeURIComponent(fixture)}`
      : `/dashboard/results?repo=${encodeURIComponent(repo)}`,
    scannedAt: result.scannedAt,
    totalPackages: result.totalPackages,
    directPackages: result.directPackages,
    transitivePackages: result.transitivePackages,
    totalFindings: result.vulnerabilities.length,
    counts: countBySeverity(result.vulnerabilities),
    findingKeys: result.vulnerabilities.map(findingKey),
  };
}

export default async function ResultsPage(props: {
  searchParams: Promise<{ repo?: string; fixture?: string }>;
}) {
  const { repo = "", fixture = "" } = await props.searchParams;

  if (!repo && !fixture) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <p className="text-sm text-[#BFC3C7]">No repository specified.</p>
        <Link
          href="/dashboard"
          className="mt-4 text-sm text-white hover:text-[#BFC3C7] transition-colors"
        >
          ← Start a scan
        </Link>
      </div>
    );
  }

  // Resolve a requested fixture before scanning, so no JSX is built inside the
  // try/catch below (a React error boundary can't catch JSX created there).
  const fx = fixture ? getFixture(fixture) : null;
  if (fixture && !fx) {
    return (
      <div className="rounded-xl border border-red-900 bg-red-950/20 px-6 py-5">
        <p className="text-sm font-medium text-red-400">
          Unknown sample &quot;{fixture}&quot;.
        </p>
      </div>
    );
  }

  let result: ScanResult;
  try {
    if (fx) {
      // Local fixture path: no GitHub fetch, only OSV. Reliable for demos.
      result = await scanProjectFiles({
        packageJson: fx.packageJson,
        packageLock: fx.packageLock,
        repo: fx.label,
        target: {
          owner: null,
          repo: null,
          branch: null,
          subpath: null,
          filesFound: ["package.json", "package-lock.json"],
          filesMissing: [],
        },
      });
    } else {
      result = await runScan(repo);
    }
  } catch {
    return (
      <div className="rounded-xl border border-red-900 bg-red-950/20 px-6 py-5">
        <p className="text-sm font-medium text-red-400">
          Unexpected error while scanning. Please try again.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Back + rescan */}
      <div className="flex items-center justify-between">
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-1.5 text-sm text-[#BFC3C7] hover:text-white transition-colors"
        >
          <svg
            className="h-4 w-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          New scan
        </Link>
      </div>

      {/* Error state */}
      {result.error ? (
        <div className="space-y-6">
          <div className="rounded-xl border border-red-900 bg-red-950/20 px-6 py-5">
            <p className="text-sm font-medium text-red-400">{result.error.message}</p>
          </div>
          <div className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-6">
            <p className="mb-4 text-sm text-[#BFC3C7]">Try a different repository:</p>
            <ScanForm defaultValue={repo} />
          </div>
        </div>
      ) : (
        <>
          <ReportSummary result={result} />

          <ScanHistoryRecorder entry={historyEntry(result, repo, fixture)} />

          {result.warnings.length > 0 && (
            <div className="rounded-xl border border-yellow-900/60 bg-yellow-950/20 px-5 py-4">
              <p className="mb-2 text-xs font-medium text-yellow-400">
                {result.warnings.length === 1 ? "Warning" : "Warnings"}
              </p>
              <ul className="space-y-1.5">
                {result.warnings.map((w, i) => (
                  <li key={i} className="text-xs text-yellow-200/80 leading-relaxed">
                    {w}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <ScanResultsTable vulnerabilities={result.vulnerabilities} />

          {/* Raw JSON report */}
          <details className="group">
            <summary className="cursor-pointer text-xs text-[#BFC3C7]/50 hover:text-[#BFC3C7] transition-colors select-none">
              View raw report JSON
            </summary>
            <pre className="mt-3 overflow-x-auto rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-4 font-mono text-xs text-[#BFC3C7] leading-relaxed">
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
        </>
      )}
    </div>
  );
}
