/**
 * Validation harness — runs the real scanner against a fixed set of repositories
 * and prints a compact report. Used to produce the evidence in validation-notes.md.
 *
 *   pnpm validate
 *
 * Hits the live GitHub + OSV APIs. Set GITHUB_TOKEN to avoid rate limits.
 */
import { runScan } from "../packages/core/src/index";
import type { ScanResult, Severity } from "../packages/core/src/types";

const CASES: Array<{ label: string; url: string }> = [
  { label: "vulnerable repo", url: "https://github.com/OWASP/NodeGoat" },
  { label: "small / low-finding repo", url: "https://github.com/sindresorhus/slugify" },
  { label: "invalid URL", url: "not-a-real-url" },
  { label: "non-GitHub URL", url: "https://gitlab.com/foo/bar" },
  { label: "repo not found", url: "https://github.com/wadmio/this-repo-does-not-exist-zzz" },
  { label: "missing package.json", url: "https://github.com/github/gitignore" },
  { label: "branch + subpath", url: "https://github.com/vercel/next.js/tree/canary/packages/next" },
];

function counts(result: ScanResult): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of result.vulnerabilities) c[v.severity]++;
  return c;
}

function report(label: string, url: string, r: ScanResult): void {
  console.log(`\n=== ${label} ===`);
  console.log(`url:     ${url}`);
  if (r.error) {
    console.log(`error:   ${r.error.code} — ${r.error.message}`);
  }
  const t = r.target;
  console.log(
    `target:  ${t.owner ?? "-"}/${t.repo ?? "-"} branch=${t.branch ?? "-"} ` +
      `found=[${t.filesFound.join(", ")}] missing=[${t.filesMissing.join(", ")}]`
  );
  console.log(
    `deps:    total=${r.totalPackages} (direct=${r.directPackages} transitive=${r.transitivePackages}) resolved=${r.resolvedPackages}`
  );
  const c = counts(r);
  const nvdCount = r.vulnerabilities.filter((v) => v.sources.includes("nvd")).length;
  console.log(
    `vulns:   total=${r.vulnerabilities.length} ` +
      `(C${c.critical} H${c.high} M${c.medium} L${c.low} U${c.unknown})` +
      ` source=${r.source}${nvdCount ? ` nvd-checked=${nvdCount}` : ""}`
  );
  if (r.warnings.length) {
    for (const w of r.warnings) console.log(`warning: ${w}`);
  }
}

async function main(): Promise<void> {
  for (const { label, url } of CASES) {
    try {
      const r = await runScan(url);
      report(label, url, r);
    } catch (err) {
      console.log(`\n=== ${label} ===`);
      console.log(`url:     ${url}`);
      console.log(`THREW:   ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  console.log("\nDone.");
}

main();
