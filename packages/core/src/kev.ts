// KEV freshness helpers — pure date math, no Node or network imports, so they
// are safe to import from client components (web) via the `@fixly/core/kev`
// subpath without dragging the whole scanner barrel (and its node:fs deps) in.

/** Days since a CVE was added to a KEV catalog, or null when unknown. */
export function kevAgeDays(dateAdded: string | null): number | null {
  if (!dateAdded) return null;
  const t = Date.parse(dateAdded);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((Date.now() - t) / 86_400_000));
}

/** True when a CVE was added to KEV within `withinDays` (default 30). */
export function isNewlyExploited(dateAdded: string | null, withinDays = 30): boolean {
  const days = kevAgeDays(dateAdded);
  return days !== null && days <= withinDays;
}
