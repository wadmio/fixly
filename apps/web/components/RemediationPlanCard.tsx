// The remediation engine's plan for this scan: a Grade Forecast (the exact
// score the project would earn with every fix applied) and the ordered list of
// actions with copy-paste commands. Server component: everything comes from
// @fixly/core's buildRemediationPlan — the same plan `fixly fix` prints.

import type { RemediationPlan, RemediationKind } from "@fixly/core";
import CopyButton from "@/components/CopyButton";
import { GRADE_TEXT } from "@/lib/grade";

const KIND_LABEL: Record<RemediationKind, { label: string; className: string }> = {
  remove: { label: "remove", className: "bg-red-950/40 text-red-400 border-red-900/60" },
  upgrade: { label: "upgrade", className: "bg-emerald-950/40 text-emerald-400 border-emerald-900/60" },
  override: { label: "override", className: "bg-yellow-950/40 text-yellow-400 border-yellow-900/60" },
};

export default function RemediationPlanCard({ plan }: { plan: RemediationPlan }) {
  if (plan.actions.length === 0) return null;

  const { before, after } = plan.forecast;

  return (
    <div className="panel p-6">
      <div className="flex items-baseline justify-between gap-4">
        <p className="microlabel">Remediation plan</p>
        <p className="text-xs text-[#6E7378]">
          same plan as <code className="font-mono">fixly fix</code>
        </p>
      </div>

      {/* Grade Forecast */}
      <p className="mt-3 text-sm text-[#9DA2A8]">
        Grade Forecast:{" "}
        <span className={`font-mono font-bold ${GRADE_TEXT[before.grade]}`}>
          {before.grade} ({before.score})
        </span>{" "}
        <span className="text-[#BFC3C7]/50">→</span>{" "}
        <span className={`font-mono font-bold ${GRADE_TEXT[after.grade]}`}>
          {after.grade} ({after.score})
        </span>{" "}
        <span className="text-[#BFC3C7]/60">
          if you apply {plan.actions.length === 1 ? "this action" : `all ${plan.actions.length} actions`}
        </span>
      </p>

      <ul className="mt-5 space-y-0">
        {plan.actions.map((action) => (
          <li
            key={`${action.package}@${action.installedVersion}`}
            className="border-t border-white/[0.05] py-3 text-xs first:border-t-0 first:pt-0 last:pb-0"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${KIND_LABEL[action.kind].className}`}
              >
                {KIND_LABEL[action.kind].label}
              </span>
              <span className="font-medium text-white">{action.package}</span>
              <span className="font-mono text-[#8B8F94]">
                {action.installedVersion}
                {action.targetVersion ? ` → ${action.targetVersion}` : ""}
              </span>
              <span className="ml-auto font-mono text-[10px] text-emerald-400/80">
                +{action.pointsRecovered} pts
              </span>
            </div>
            <p className="mt-1 text-[#9DA2A8]">{action.reason}</p>
            <span className="mt-1.5 flex w-fit items-center gap-1.5">
              <code className="rounded-md border border-white/[0.06] bg-[#0A0A0B] px-2 py-1 font-mono text-[11px] text-emerald-400">
                $ {action.command}
              </code>
              <CopyButton text={action.command} />
            </span>
          </li>
        ))}
      </ul>

      {plan.unfixable.length > 0 && (
        <p className="mt-4 border-t border-white/[0.05] pt-3 text-xs text-[#6E7378]">
          {plan.unfixable.length} finding{plan.unfixable.length === 1 ? " has" : "s have"} no
          published fix yet ({plan.unfixable.map((u) => u.package).join(", ")}) — kept in the
          forecast.
        </p>
      )}
    </div>
  );
}
