// Typosquat / hallucination-adjacency detection — pure string analysis, no
// network. Flags package names that are suspiciously close to a very popular
// package: classic typosquats ("lodahs") and the AI-era variant, slopsquats —
// names LLMs hallucinate near real ones ("unused-imports" for
// "eslint-plugin-unused-imports"), which attackers pre-register.
//
// Deliberately conservative: a match here is a SIGNAL to combine with registry
// evidence (package age, downloads), never a verdict on its own — plenty of
// legitimate packages have short names near other packages.

import { POPULAR_PACKAGES, isPopularPackage } from "./popular-packages";

/** Strip scope and separators so "@scope/fast-glob" ~ "fastglob" compare. */
function normalizeName(name: string): string {
  return name.toLowerCase().replace(/^@[^/]+\//, "").replace(/[-_.]/g, "");
}

/**
 * Optimal string alignment distance (Damerau-Levenshtein without repeated
 * transpositions) — insertions, deletions, substitutions, adjacent swaps all
 * cost 1. Classic typos ("lodahs" → "lodash") score 1.
 */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const d: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

// Prefix/suffix families LLMs commonly drop or invent when "remembering" a
// package name. "unused-imports" is a documented real-world slopsquat of
// "eslint-plugin-unused-imports".
const PLUGIN_PREFIXES = [
  "eslint-plugin-",
  "babel-plugin-",
  "rollup-plugin-",
  "vite-plugin-",
  "webpack-plugin-",
  "postcss-",
  "remark-",
  "rehype-",
  "node-",
  "js-",
];
const NAME_SUFFIXES = ["-js", ".js", "-node", "-cli", "-api", "-sdk", "-lib"];

export interface TyposquatMatch {
  /** The popular package this name is suspiciously close to. */
  target: string;
  /** How it matched: an edit-distance typo or a dropped/added affix. */
  kind: "typo" | "affix";
}

/**
 * Return the popular package `name` is suspiciously close to, or null.
 * Exact members of the popular list are never flagged.
 */
export function findTyposquatTarget(name: string): TyposquatMatch | null {
  const lower = name.toLowerCase();
  if (isPopularPackage(lower)) return null;

  // Affix confusion: "<popular>" minus/plus a common prefix or suffix.
  for (const prefix of PLUGIN_PREFIXES) {
    if (POPULAR_PACKAGES.has(prefix + lower)) return { target: prefix + lower, kind: "affix" };
    if (lower.startsWith(prefix) && POPULAR_PACKAGES.has(lower.slice(prefix.length))) {
      return { target: lower.slice(prefix.length), kind: "affix" };
    }
  }
  for (const suffix of NAME_SUFFIXES) {
    if (POPULAR_PACKAGES.has(lower + suffix)) return { target: lower + suffix, kind: "affix" };
    if (lower.endsWith(suffix) && POPULAR_PACKAGES.has(lower.slice(0, -suffix.length))) {
      return { target: lower.slice(0, -suffix.length), kind: "affix" };
    }
  }

  // Edit-distance typos, on normalized names (separators are free): distance 1
  // always suspicious; distance 2 only for longer names where 2 typos still
  // land near the original.
  const norm = normalizeName(lower);
  let best: { target: string; distance: number } | null = null;
  for (const popular of POPULAR_PACKAGES) {
    const popNorm = normalizeName(popular);
    if (popNorm === norm && popular !== lower) {
      // Same letters, different separators/scope ("fast-glob" vs "fastglob").
      return { target: popular, kind: "typo" };
    }
    // Cheap length guard before computing the matrix.
    if (Math.abs(popNorm.length - norm.length) > 2) continue;
    const distance = editDistance(norm, popNorm);
    const threshold = popNorm.length >= 8 ? 2 : 1;
    if (distance > 0 && distance <= threshold && (!best || distance < best.distance)) {
      best = { target: popular, distance };
    }
  }

  return best ? { target: best.target, kind: "typo" } : null;
}
