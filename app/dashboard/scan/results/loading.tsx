export default function Loading() {
  return (
    <div className="flex flex-col items-center justify-center py-32 gap-4">
      <div className="h-6 w-6 rounded-full border-2 border-[#D1D5DB]/20 border-t-white animate-spin" />
      <p className="text-sm text-[#BFC3C7]">Scanning repository…</p>
      <p className="text-xs text-[#BFC3C7]/40">
        Fetching packages and querying OSV
      </p>
    </div>
  );
}
