// Skeleton that mirrors the report layout (actions row → summary → score
// ring → table), so the page appears to assemble rather than pop in.

function Bar({ className }: { className: string }) {
  return <div className={`animate-pulse rounded bg-white/5 ${className}`} />;
}

export default function Loading() {
  return (
    <div className="space-y-8" aria-busy="true" aria-live="polite">
      <div className="flex items-center justify-between">
        <Bar className="h-5 w-24" />
        <div className="flex gap-2">
          <Bar className="h-7 w-20" />
          <Bar className="h-7 w-28" />
          <Bar className="h-7 w-24" />
        </div>
      </div>

      <div className="space-y-3">
        <Bar className="h-6 w-64" />
        <Bar className="h-4 w-96 max-w-full" />
      </div>

      <div className="panel grid grid-cols-1 gap-6 p-6 sm:grid-cols-[1fr_1fr_2.2fr]">
        <div className="space-y-2">
          <Bar className="h-8 w-16" />
          <Bar className="h-3 w-20" />
        </div>
        <div className="space-y-2">
          <Bar className="h-8 w-12" />
          <Bar className="h-3 w-20" />
        </div>
        <div className="space-y-2">
          <Bar className="h-3 w-32" />
          <Bar className="h-2 w-full" />
          <Bar className="h-3 w-48" />
        </div>
      </div>

      <div className="panel flex items-center gap-7 p-7">
        <div className="h-28 w-28 shrink-0 animate-pulse rounded-full border-4 border-white/5" />
        <div className="flex-1 space-y-2">
          <Bar className="h-4 w-32" />
          <Bar className="h-3 w-72 max-w-full" />
          <Bar className="h-3 w-56 max-w-full" />
        </div>
      </div>

      <div className="panel overflow-hidden">
        <div className="border-b border-white/[0.05] p-4">
          <Bar className="h-3 w-full" />
        </div>
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="border-b border-white/[0.05] p-4 last:border-b-0">
            <Bar className="h-4 w-full" />
          </div>
        ))}
      </div>

      <p className="text-center text-xs text-[#6E7378]">
        Scanning — checking every package against OSV…
      </p>
    </div>
  );
}
