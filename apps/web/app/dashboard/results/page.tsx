import Link from "next/link";
import type { Metadata } from "next";
import {
  runScan,
  scanProjectFiles,
  findingKey,
  countBySeverity,
  computeGrade,
  buildRemediationPlan,
  type ScanResult,
} from "@fixly/core";
import { parseGitHubUrl } from "@fixly/core/url";
import RemediationPlanCard from "@/components/RemediationPlanCard";
import ReportActions from "@/components/ReportActions";
import ReportSummary from "@/components/ReportSummary";
import ScoreCard from "@/components/ScoreCard";
import ScanResultsTable from "@/components/ScanResultsTable";
import ScanForm from "@/components/ScanForm";
import ScanHistoryRecorder from "@/components/ScanHistoryRecorder";
import { getFixture } from "@/lib/fixtures";
import { buildSummaryText } from "@/lib/summary";
import type { ScanHistoryEntry } from "@/lib/history";

type ResultsSearchParams = Promise<{ repo?: string; fixture?: string }>;

export async function generateMetadata(props: {
  searchParams: ResultsSearchParams;
}): Promise<Metadata> {
  const { repo = "", fixture = "" } = await props.searchParams;
  if (fixture) {
    const fx = getFixture(fixture);
    return { title: fx ? `${fx.label} — scan report` : "Scan report" };
  }
  const parsed = repo ? parseGitHubUrl(repo) : null;
  return {
    title: parsed ? `${parsed.owner}/${parsed.repo} — scan report` : "Scan report",
  };
}

// Compact, serializable summary handed to the client-side history recorder.
function historyEntry(
  result: ScanResult,
  repo: string,
  fixture: string,
  grade: ReturnType<typeof computeGrade>
): ScanHistoryEntry {
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
    grade: grade.grade,
    score: grade.score,
  };
}

function BackLink() {
  return (
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
        aria-hidden="true"
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
      </svg>
      New scan
    </Link>
  );
}

export default async function ResultsPage(props: {
  searchParams: ResultsSearchParams;
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
      <div className="space-y-6">
        <BackLink />
        <div className="rounded-xl border border-red-400/20 bg-red-400/[0.06] px-6 py-5">
          <p className="text-sm font-medium text-red-400">
            Unknown sample &quot;{fixture}&quot;.
          </p>
        </div>
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
    // Same recovery affordances as the structured-error branch below — a
    // thrown scan error must not dead-end the user.
    return (
      <div className="space-y-6">
        <BackLink />
        <div className="rounded-xl border border-red-400/20 bg-red-400/[0.06] px-6 py-5">
          <p className="text-sm font-medium text-red-400">
            Unexpected error while scanning. Please try again.
          </p>
        </div>
        <div className="panel p-6">
          <p className="mb-4 text-sm text-[#9DA2A8]">Try again or scan a different repository:</p>
          <ScanForm defaultValue={repo} />
        </div>
      </div>
    );
  }

  if (result.error) {
    return (
      <div className="space-y-6">
        <BackLink />
        <div className="rounded-xl border border-red-400/20 bg-red-400/[0.06] px-6 py-5">
          <p className="text-sm font-medium text-red-400">{result.error.message}</p>
        </div>
        <div className="panel p-6">
          <p className="mb-4 text-sm text-[#9DA2A8]">Try a different repository:</p>
          <ScanForm defaultValue={repo} />
        </div>
      </div>
    );
  }

  const grade = computeGrade(result);
  const plan = buildRemediationPlan(result);
  const repoSlug = result.repo
    .replace(/^https?:\/\/github\.com\//, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return (
    <div className="space-y-8">
      {/* Back + report actions */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <BackLink />
        <ReportActions
          summaryText={buildSummaryText(result)}
          jsonText={JSON.stringify(result, null, 2)}
          fileName={`fixly-${repoSlug || "scan"}.json`}
        />
      </div>

      <ReportSummary result={result} />

      <ScoreCard grade={grade} plan={plan} />

      <RemediationPlanCard plan={plan} />

      <ScanHistoryRecorder entry={historyEntry(result, repo, fixture, grade)} />

      {result.warnings.length > 0 && (
        <div className="rounded-xl border border-amber-400/15 bg-amber-400/[0.05] px-5 py-4">
          <p className="microlabel mb-2 !text-amber-400/90">
            {result.warnings.length === 1 ? "Warning" : "Warnings"}
          </p>
          <ul className="space-y-1.5">
            {result.warnings.map((w, i) => (
              <li key={i} className="text-xs text-amber-100/70 leading-relaxed">
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
        <pre className="panel mt-3 overflow-x-auto p-4 font-mono text-xs text-[#9DA2A8] leading-relaxed">
          {JSON.stringify(result, null, 2)}
        </pre>
      </details>

      <p className="flex flex-wrap gap-x-2 text-[11px] text-[#BFC3C7]/40">
        <span>Scanned {new Date(result.scannedAt).toLocaleString("en-US")}</span>
        <span aria-hidden="true">·</span>
        <span>{result.source === "osv+nvd" ? "OSV + NVD" : "OSV"}</span>
        <span aria-hidden="true">·</span>
        <span>Fixly — detect · remediate · verify</span>
      </p>
    </div>
  );
}
