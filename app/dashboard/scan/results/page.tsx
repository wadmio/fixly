import Link from "next/link";
import { runScan } from "@/lib/scan";
import ReportSummary from "@/components/ReportSummary";
import ScanResultsTable from "@/components/ScanResultsTable";
import ScanForm from "@/components/ScanForm";

export default async function ResultsPage(props: {
  searchParams: Promise<{ repo?: string }>;
}) {
  const { repo = "" } = await props.searchParams;

  if (!repo) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <p className="text-sm text-[#BFC3C7]">No repository specified.</p>
        <Link
          href="/dashboard/scan"
          className="mt-4 text-sm text-white hover:text-[#BFC3C7] transition-colors"
        >
          ← Start a scan
        </Link>
      </div>
    );
  }

  let result;
  try {
    result = await runScan(repo);
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
          href="/dashboard/scan"
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
            <p className="text-sm font-medium text-red-400">{result.error}</p>
          </div>
          <div className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-6">
            <p className="mb-4 text-sm text-[#BFC3C7]">Try a different repository:</p>
            <ScanForm defaultValue={repo} />
          </div>
        </div>
      ) : (
        <>
          <ReportSummary result={result} />
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
