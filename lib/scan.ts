import { parseGitHubUrl, fetchProjectFiles } from "./github";
import { parsePackages } from "./parse-packages";
import { queryOsvBatch } from "./osv";
import { normalizeOsvResults } from "./normalize";
import type { ScanResult, Severity } from "./types";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export async function runScan(repoUrl: string): Promise<ScanResult> {
  const base = {
    repo: repoUrl,
    scannedAt: new Date().toISOString(),
    source: "osv" as const,
  };

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return {
      ...base,
      totalPackages: 0,
      vulnerabilities: [],
      error:
        "Invalid GitHub URL. Please use a public github.com repository URL (e.g. https://github.com/owner/repo).",
    };
  }

  const { owner, repo, branch, subpath } = parsed;
  const { packageJson, packageLock, error } = await fetchProjectFiles(owner, repo, branch, subpath);

  if (!packageJson) {
    const msg =
      error === "private"
        ? `${owner}/${repo} is private or requires authentication. Only public repositories are supported.`
        : `No package.json found in ${owner}/${repo}. This may not be a Node.js project, or the file may be in a subdirectory.`;
    return { ...base, totalPackages: 0, vulnerabilities: [], error: msg };
  }

  const packages = parsePackages(packageJson, packageLock);

  if (packages.length === 0) {
    return {
      ...base,
      totalPackages: 0,
      vulnerabilities: [],
      error: "No resolvable packages found in package.json.",
    };
  }

  let osvResults;
  try {
    osvResults = await queryOsvBatch(packages);
  } catch (err) {
    return {
      ...base,
      totalPackages: packages.length,
      vulnerabilities: [],
      error: `OSV query failed: ${err instanceof Error ? err.message : "Unknown error"}`,
    };
  }

  const vulnerabilities = [];
  for (const [pkgName, vulns] of osvResults.entries()) {
    const pkg = packages.find((p) => p.name === pkgName);
    if (!pkg) continue;
    vulnerabilities.push(...normalizeOsvResults(pkgName, pkg.version, vulns));
  }

  vulnerabilities.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  return {
    ...base,
    totalPackages: packages.length,
    vulnerabilities,
  };
}
