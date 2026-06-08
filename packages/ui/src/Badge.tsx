import { severityBadgeStyle, severityLabel } from "./severity";

export interface BadgeProps {
  severity: string;
}

export function Badge({ severity }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${severityBadgeStyle(severity)}`}
    >
      {severityLabel(severity)}
    </span>
  );
}
