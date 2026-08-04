// The Fixly Score — the report's hero. Same treatment as the VS Code
// extension's webview, elevated: an SVG progress ring filled to the score
// with a soft grade-colored glow, the grade letter inside, the headline, a
// one-line Grade Forecast, and the fixes that recover the most points (each
// with a one-click copy). Server component: everything is computed by
// @fixly/core's computeGrade / buildRemediationPlan.

import type { RemediationPlan, ScanGrade } from "@fixly/core";
import CopyButton from "@/components/CopyButton";
import { GRADE_HEX, GRADE_TEXT } from "@/lib/grade";

// Ring geometry: r=36 → circumference ≈ 226.2 (matches the extension);
// rendered at 112px for presence.
const RING_C = 226.2;

export default function ScoreCard({
  grade,
  plan,
}: {
  grade: ScanGrade;
  plan?: RemediationPlan;
}) {
  const hex = GRADE_HEX[grade.grade];
  const dash = (Math.max(0, Math.min(100, grade.score)) / 100) * RING_C;
  const forecast = plan && plan.actions.length > 0 ? plan.forecast : null;

  return (
    <div className="panel relative overflow-hidden p-7">
      {/* Grade-colored ambient glow behind the ring. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -left-16 -top-16 h-64 w-64 rounded-full opacity-[0.13] blur-3xl"
        style={{ background: hex }}
      />

      <div className="relative flex items-start gap-7">
        {/* Score ring */}
        <div
          className="relative h-28 w-28 shrink-0"
          role="img"
          aria-label={`Fixly Score ${grade.grade}, ${grade.score} out of 100`}
        >
          <svg className="h-28 w-28" viewBox="0 0 84 84" aria-hidden="true">
            <circle cx="42" cy="42" r="36" fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="4.5" />
            <circle
              cx="42"
              cy="42"
              r="36"
              fill="none"
              stroke={hex}
              strokeWidth="4.5"
              strokeLinecap="round"
              strokeDasharray={`${dash} ${RING_C}`}
              transform="rotate(-90 42 42)"
              className="animate-ring-fill"
            />
          </svg>
          <span
            className={`absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 text-4xl font-bold tracking-tight ${GRADE_TEXT[grade.grade]}`}
          >
            {grade.grade}
          </span>
        </div>

        <div className="min-w-0 flex-1 pt-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <p className="microlabel">Fixly Score</p>
            <p className="font-mono text-lg font-semibold tabular-nums text-white">
              {grade.score}
              <span className="text-xs font-normal text-[#8B8F94]">/100</span>
            </p>
          </div>
          <p className="mt-1.5 max-w-xl text-sm text-[#C9CDD1] leading-relaxed">{grade.headline}</p>

          {forecast && (
            <p className="mt-3 border-t border-white/[0.06] pt-3 text-sm text-[#9DA2A8]">
              Fix everything →{" "}
              <span className={`font-mono font-semibold ${GRADE_TEXT[forecast.after.grade]}`}>
                {forecast.after.grade} ({forecast.after.score}/100)
              </span>
              <span className="text-[#6E7378]">
                {" "}· {plan!.actions.length} action{plan!.actions.length === 1 ? "" : "s"}
              </span>
            </p>
          )}

          {grade.topFixes.length > 0 && (
            <div className="mt-4">
              <p className="microlabel">Fix these first</p>
              <ul className="mt-2 space-y-2">
                {grade.topFixes.map((fix) => (
                  <li key={`${fix.package}@${fix.installedVersion}`} className="text-xs">
                    <span className="font-medium text-white">{fix.package}</span>
                    <span className="font-mono text-[#8B8F94]">@{fix.installedVersion}</span>{" "}
                    <span className="text-[#9DA2A8]">— {fix.reason}</span>
                    {fix.command && (
                      <span className="mt-1 flex w-fit items-center gap-1.5">
                        <code className="rounded-md border border-white/[0.06] bg-[#0A0A0B] px-2 py-1 font-mono text-[11px] text-emerald-400">
                          $ {fix.command}
                        </code>
                        <CopyButton text={fix.command} />
                      </span>
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
