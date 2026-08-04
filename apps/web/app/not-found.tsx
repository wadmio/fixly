import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-full flex-col items-center justify-center gap-4 bg-[#0A0A0A] py-32 text-center">
      <p className="font-mono text-5xl font-bold text-[#BFC3C7]/30">404</p>
      <p className="text-sm text-[#BFC3C7]">This page doesn&apos;t exist.</p>
      <Link
        href="/dashboard"
        className="rounded-lg bg-white px-4 py-2 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors"
      >
        Go to the scanner
      </Link>
    </div>
  );
}
