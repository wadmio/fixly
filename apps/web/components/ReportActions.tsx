"use client";

// Report toolbar — the same actions the VS Code extension's webview offers
// (Rescan / Copy Summary / Export JSON), plus Copy Link since a web scan is
// shareable by URL. All content is precomputed on the server and passed in.

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

type Feedback = "summary" | "link" | null;

export default function ReportActions({
  summaryText,
  jsonText,
  fileName,
}: {
  summaryText: string;
  jsonText: string;
  fileName: string;
}) {
  const router = useRouter();
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [rescanning, setRescanning] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  function flash(kind: Exclude<Feedback, null>) {
    setFeedback(kind);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setFeedback(null), 1500);
  }

  async function copy(text: string, kind: Exclude<Feedback, null>) {
    try {
      await navigator.clipboard.writeText(text);
      flash(kind);
    } catch {
      // Clipboard unavailable — no-op.
    }
  }

  function rescan() {
    setRescanning(true);
    router.refresh();
    // refresh() gives no completion signal; re-enable after a beat so the
    // button can't be hammered while the server re-renders.
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setRescanning(false), 4000);
  }

  function exportJson() {
    const blob = new Blob([jsonText], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  const buttonCls =
    "rounded-md border border-white/[0.12] px-3.5 py-1.5 text-xs font-medium text-[#C9CDD1] hover:bg-white/[0.06] hover:text-white transition-colors disabled:opacity-50";

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" onClick={rescan} disabled={rescanning} className={buttonCls}>
        {rescanning ? "Rescanning…" : "Rescan"}
      </button>
      <button type="button" onClick={() => copy(summaryText, "summary")} className={buttonCls}>
        {feedback === "summary" ? "Copied ✓" : "Copy summary"}
      </button>
      <button type="button" onClick={exportJson} className={buttonCls}>
        Export JSON
      </button>
      <button
        type="button"
        onClick={() => copy(window.location.href, "link")}
        className={buttonCls}
      >
        {feedback === "link" ? "Copied ✓" : "Copy link"}
      </button>
    </div>
  );
}
