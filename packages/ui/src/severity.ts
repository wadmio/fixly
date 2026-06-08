// Shared severity presentation helpers. Tailwind utility classes here are
// static string literals so they are detected by the consuming app's
// Tailwind content scan (see the web app's `@source` directive).

export const SEVERITY_BADGE_STYLES: Record<string, string> = {
  critical: "bg-red-950 text-red-400 ring-red-900",
  high: "bg-orange-950 text-orange-400 ring-orange-900",
  medium: "bg-yellow-950 text-yellow-400 ring-yellow-900",
  low: "bg-blue-950 text-blue-400 ring-blue-900",
  unknown: "bg-[#1A1A1A] text-[#BFC3C7] ring-[#D1D5DB]/20",
};

export const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
};

export function severityBadgeStyle(severity: string): string {
  return SEVERITY_BADGE_STYLES[severity] ?? SEVERITY_BADGE_STYLES.unknown;
}

export function severityLabel(severity: string): string {
  return SEVERITY_LABELS[severity] ?? severity;
}
