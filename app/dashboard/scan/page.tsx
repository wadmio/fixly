import ScanForm from "@/components/ScanForm";

export default function ScanPage() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center py-20">
      <div className="w-full max-w-lg">
        <div className="mb-8">
          <h1 className="text-xl font-semibold text-white">Scan a repository</h1>
          <p className="mt-1.5 text-sm text-[#BFC3C7]">
            Paste a public GitHub URL. Fixly will fetch your{" "}
            <span className="font-mono text-xs">package.json</span>, resolve versions from the
            lock file if available, and check every package against OSV.
          </p>
        </div>
        <ScanForm />
      </div>
    </div>
  );
}
