// The Fixly Score — the report's headline. One glanceable grade, the honest
// headline, and the fixes that recover the most points. Server component:
// everything is computed by @fixly/core's computeGrade.

import type { ScanGrade, Grade } from "@fixly/core";

const GRADE_STYLES: Record<Grade, { text: string; border: string; bg: string }> = {
  A: { text: "text-emerald-400", border: "border-emerald-900/60", bg: "bg-emerald-950/20" },
  B: { text: "text-cyan-400", border: "border-cyan-900/60", bg: "bg-cyan-950/20" },
  C: { text: "text-yellow-400", border: "border-yellow-900/60", bg: "bg-yellow-950/20" },
  D: { text: "text-orange-400", border: "border-orange-900/60", bg: "bg-orange-950/20" },
  F: { text: "text-red-400", border: "border-red-900/60", bg: "bg-red-950/20" },
};

export default function ScoreCard({ grade }: { grade: ScanGrade }) {
  const styles = GRADE_STYLES[grade.grade];

  return (
    <div className={`rounded-xl border ${styles.border} ${styles.bg} p-6`}>
      <div className="flex items-start gap-5">
        {/* The letter */}
        <div
          className={`flex h-20 w-20 shrink-0 items-center justify-center rounded-xl border ${styles.border} bg-[#0A0A0A]`}
        >
          <span className={`text-5xl font-bold ${styles.text}`}>{grade.grade}</span>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <p className="text-sm font-semibold text-white">Fixly Score</p>
            <p className="font-mono text-xs text-[#BFC3C7]/60">{grade.score}/100</p>
          </div>
          <p className="mt-1 text-sm text-[#BFC3C7] leading-snug">{grade.headline}</p>

          {grade.topFixes.length > 0 && (
            <div className="mt-4">
              <p className="text-xs font-medium text-white">Fix these first</p>
              <ul className="mt-1.5 space-y-1.5">
                {grade.topFixes.map((fix) => (
                  <li key={`${fix.package}@${fix.installedVersion}`} className="text-xs">
                    <span className="font-medium text-white">{fix.package}</span>
                    <span className="font-mono text-[#BFC3C7]/60">@{fix.installedVersion}</span>{" "}
                    <span className="text-[#BFC3C7]/70">— {fix.reason}</span>
                    {fix.command && (
                      <code className="mt-0.5 block w-fit rounded bg-[#0A0A0A] px-2 py-1 font-mono text-[11px] text-emerald-400">
                        $ {fix.command}
                      </code>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
