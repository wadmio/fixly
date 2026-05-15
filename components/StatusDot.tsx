type Status = "completed" | "running" | "failed";

const styles: Record<Status, string> = {
  completed: "bg-emerald-500",
  running: "bg-blue-500 animate-pulse",
  failed: "bg-red-500",
};

const labels: Record<Status, string> = {
  completed: "Completed",
  running: "Running",
  failed: "Failed",
};

export default function StatusDot({ status }: { status: Status }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`inline-block h-2 w-2 rounded-full ${styles[status]}`} />
      <span className="text-sm text-[#BFC3C7]">{labels[status]}</span>
    </span>
  );
}
