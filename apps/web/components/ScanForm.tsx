"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function ScanForm({ defaultValue = "" }: { defaultValue?: string }) {
  const [url, setUrl] = useState(defaultValue);
  const [error, setError] = useState("");
  const router = useRouter();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a GitHub repository URL.");
      return;
    }
    if (!trimmed.includes("github.com")) {
      setError("Only public GitHub repositories are supported.");
      return;
    }
    setError("");
    router.push(`/dashboard/results?repo=${encodeURIComponent(trimmed)}`);
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <div className="flex gap-2">
        <input
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError("");
          }}
          placeholder="https://github.com/owner/repo"
          className="flex-1 rounded-lg border border-[#D1D5DB]/20 bg-[#1A1A1A] px-4 py-2.5 text-sm text-white placeholder-[#BFC3C7]/40 focus:border-[#D1D5DB]/50 focus:outline-none transition-colors"
          autoFocus
        />
        <button
          type="submit"
          className="rounded-lg bg-white px-4 py-2.5 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors whitespace-nowrap"
        >
          Scan repo
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <p className="text-xs text-[#BFC3C7]/50">
        Public repositories only · No authentication required
      </p>
    </form>
  );
}
