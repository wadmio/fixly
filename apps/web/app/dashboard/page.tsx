import Link from "next/link";
import type { Metadata } from "next";
import ScanForm from "@/components/ScanForm";
import RecentScans from "@/components/RecentScans";

export const metadata: Metadata = {
  title: "Scan a repository",
};

const scope = [
  "Public GitHub repositories only — no authentication required or supported.",
  "npm ecosystem only — reads package.json and package-lock.json.",
  "Direct AND transitive dependencies — the full lock file tree is checked (with a lock file; without one, direct only).",
  "Detection via the OSV database (api.osv.dev); CVEs are cross-referenced against NVD for a second severity opinion.",
  "Scan history is stored in this browser only — no accounts, no server-side storage.",
];

export default function DashboardPage() {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-8 py-10">
      <div>
        <h1 className="text-xl font-semibold text-white">Scan a repository</h1>
        <p className="mt-1.5 text-sm text-[#BFC3C7]">
          Paste a public GitHub URL. Fixly fetches the project&apos;s{" "}
          <span className="font-mono text-xs">package.json</span> and lock file, checks
          every installed package — direct and transitive — against OSV, and
          cross-references CVEs with NVD.
        </p>
      </div>

      <ScanForm />

      <div className="-mt-2 flex items-center gap-2.5">
        <Link
          href="/dashboard/results?fixture=vulnerable-demo"
          className="rounded-lg border border-[#D1D5DB]/20 px-3 py-1.5 text-xs font-medium text-[#BFC3C7] hover:border-[#D1D5DB]/40 hover:text-white transition-colors"
        >
          Try a sample scan
        </Link>
        <p className="text-xs text-[#BFC3C7]/60">
          A bundled project of known-vulnerable packages — no GitHub needed.
        </p>
      </div>

      <RecentScans />

      <div className="panel p-5">
        <p className="microlabel mb-3">Current scope</p>
        <ul className="space-y-1.5">
          {scope.map((item) => (
            <li
              key={item}
              className="flex gap-2 text-xs text-[#9DA2A8] leading-relaxed"
            >
              <span className="text-[#6E7378]">—</span>
              {item}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
