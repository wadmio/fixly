// Single source of truth for the A–F grade presentation on the web surface.
// Mirrors the extension's GRADE_COLORS (panel-render.ts) — emerald/cyan/
// yellow/orange/red 400s — so every Fixly surface grades in the same palette.

import type { Grade } from "@fixly/core";

/** Tailwind text color per grade (client-safe: plain strings). */
export const GRADE_TEXT: Record<Grade, string> = {
  A: "text-emerald-400",
  B: "text-cyan-400",
  C: "text-yellow-400",
  D: "text-orange-400",
  F: "text-red-400",
};

/** Border + background treatment per grade (score card). */
export const GRADE_SURFACE: Record<Grade, { border: string; bg: string }> = {
  A: { border: "border-emerald-900/60", bg: "bg-emerald-950/20" },
  B: { border: "border-cyan-900/60", bg: "bg-cyan-950/20" },
  C: { border: "border-yellow-900/60", bg: "bg-yellow-950/20" },
  D: { border: "border-orange-900/60", bg: "bg-orange-950/20" },
  F: { border: "border-red-900/60", bg: "bg-red-950/20" },
};

/** Raw hex per grade — for SVG strokes (the score ring). */
export const GRADE_HEX: Record<Grade, string> = {
  A: "#34d399",
  B: "#22d3ee",
  C: "#facc15",
  D: "#fb923c",
  F: "#f87171",
};

/** Raw hex per severity — for the distribution bar segments and dots. */
export const SEVERITY_HEX: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#facc15",
  low: "#60a5fa",
  unknown: "#8b8f94",
};
