const styles: Record<string, string> = {
  critical: "bg-red-950 text-red-400 ring-red-900",
  high: "bg-orange-950 text-orange-400 ring-orange-900",
  medium: "bg-yellow-950 text-yellow-400 ring-yellow-900",
  low: "bg-blue-950 text-blue-400 ring-blue-900",
  unknown: "bg-[#1A1A1A] text-[#BFC3C7] ring-[#D1D5DB]/20",
};

const labels: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
};

export default function Badge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${styles[severity] ?? styles.unknown}`}
    >
      {labels[severity] ?? severity}
    </span>
  );
}
