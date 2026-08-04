"use client";

// Route-level error boundary — catches render errors the page's try/catch
// can't (they happen after the scan, during React rendering).

import Link from "next/link";

export default function ResultsError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-24 text-center">
      <p className="text-sm font-medium text-red-400">
        Something went wrong while rendering this report.
      </p>
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={reset}
          className="rounded-lg bg-white px-4 py-2 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors"
        >
          Try again
        </button>
        <Link
          href="/dashboard"
          className="rounded-lg border border-[#D1D5DB]/20 px-4 py-2 text-sm text-[#BFC3C7] hover:border-[#D1D5DB]/40 hover:text-white transition-colors"
        >
          New scan
        </Link>
      </div>
    </div>
  );
}
