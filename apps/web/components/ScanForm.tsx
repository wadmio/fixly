"use client";

import { useId, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { parseGitHubUrl } from "@fixly/core/url";

export default function ScanForm({ defaultValue = "" }: { defaultValue?: string }) {
  const [url, setUrl] = useState(defaultValue);
  const [error, setError] = useState("");
  const [pending, startTransition] = useTransition();
  const router = useRouter();
  const errorId = useId();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (pending) return;
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a GitHub repository URL.");
      return;
    }
    if (!parseGitHubUrl(trimmed)) {
      setError(
        "Enter a valid public GitHub URL, e.g. https://github.com/owner/repo"
      );
      return;
    }
    setError("");
    // The results route scans server-side, so the navigation stays pending
    // until the scan finishes — the button reflects that instead of going dead.
    startTransition(() => {
      router.push(`/dashboard/results?repo=${encodeURIComponent(trimmed)}`);
    });
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3">
      <div className="flex gap-2">
        <label htmlFor={`repo-url-${errorId}`} className="sr-only">
          Public GitHub repository URL
        </label>
        <input
          id={`repo-url-${errorId}`}
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError("");
          }}
          placeholder="https://github.com/owner/repo"
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
          disabled={pending}
          className="flex-1 rounded-lg border border-white/[0.1] bg-[#111214] px-4 py-2.5 text-sm text-white shadow-[inset_0_1px_2px_rgba(0,0,0,0.3)] placeholder-[#6E7378] focus:border-white/[0.25] focus:outline-none transition-colors disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={pending}
          className="inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-medium text-[#0A0A0A] hover:bg-[#BFC3C7] transition-colors whitespace-nowrap disabled:opacity-70 disabled:hover:bg-white"
        >
          {pending && (
            <span
              className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[#0A0A0A]/20 border-t-[#0A0A0A]"
              aria-hidden="true"
            />
          )}
          {pending ? "Scanning…" : "Scan repo"}
        </button>
      </div>
      {error && (
        <p id={errorId} role="alert" className="text-xs text-red-400">
          {error}
        </p>
      )}
      <p className="text-xs text-[#BFC3C7]/50">
        Public repositories only · No authentication required
      </p>
    </form>
  );
}
