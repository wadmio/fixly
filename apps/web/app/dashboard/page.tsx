import Link from "next/link";
import ScanForm from "@/components/ScanForm";
import RecentScans from "@/components/RecentScans";

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

      <p className="-mt-4 text-xs text-[#BFC3C7]/70">
        No URL handy?{" "}
        <Link
          href="/dashboard/results?fixture=vulnerable-demo"
          className="text-white underline-offset-2 hover:underline"
        >
          Try a sample scan
        </Link>{" "}
        — a bundled project of known-vulnerable packages (no GitHub needed).
      </p>

      <RecentScans />

      <div className="rounded-xl border border-[#D1D5DB]/10 bg-[#1A1A1A] p-5">
        <p className="mb-3 text-xs font-medium text-white">Current scope</p>
        <ul className="space-y-1.5">
          {scope.map((item) => (
            <li
              key={item}
              className="flex gap-2 text-xs text-[#BFC3C7] leading-relaxed"
            >
              <span className="text-[#BFC3C7]/40">—</span>
              {item}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
