export interface GitHubRepo {
  owner: string;
  repo: string;
  branch?: string;   // extracted from /tree/<branch>/...
  subpath?: string;  // extracted from /tree/<branch>/<subpath>
}

export interface ProjectFiles {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageJson: any | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageLock: any | null;
  branch: string | null;
  error?: "not_found" | "private" | "no_package_json";
}

export function parseGitHubUrl(url: string): GitHubRepo | null {
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    if (parsed.hostname !== "github.com") return null;

    // pathname: /owner/repo[/tree/branch[/subpath...]]
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;

    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/, "");

    // /tree/<branch>[/<subpath>]
    if (parts[2] === "tree" && parts[3]) {
      const branch = parts[3];
      const subpath = parts.slice(4).join("/") || undefined;
      return { owner, repo, branch, subpath };
    }

    return { owner, repo };
  } catch {
    return null;
  }
}

const GH_HEADERS = {
  Accept: "application/vnd.github.v3+json",
  "User-Agent": "fixly-scanner/1.0",
};

interface ContentsApiResponse {
  encoding?: string;
  content?: string;
}

/**
 * Fetch a file's content via the GitHub Contents API.
 * Returns the decoded text, or null if not found.
 * Throws "private" on 401/403 so callers can surface a clear error.
 */
async function fetchViaContentsApi(
  owner: string,
  repo: string,
  path: string
): Promise<string | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
  const res = await fetch(url, { headers: GH_HEADERS });

  if (res.status === 404) return null;
  if (res.status === 403 || res.status === 401) {
    throw new Error("private");
  }
  if (!res.ok) {
    throw new Error(`github_api_${res.status}`);
  }

  const data = (await res.json()) as ContentsApiResponse;

  if (data.encoding === "base64" && typeof data.content === "string") {
    return Buffer.from(data.content.replace(/\n/g, ""), "base64").toString("utf-8");
  }

  return null;
}

/**
 * Fallback: fetch raw content directly (needs a known branch name).
 */
async function fetchRawFallback(
  owner: string,
  repo: string,
  branch: string,
  path: string
): Promise<string | null> {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "fixly-scanner/1.0" },
    });
    if (!res.ok) return null;
    return res.text();
  } catch {
    return null;
  }
}

/**
 * Get the default branch of a repo via the GitHub API.
 */
async function getDefaultBranch(owner: string, repo: string): Promise<string> {
  try {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: GH_HEADERS,
    });
    if (!res.ok) return "main";
    const data = (await res.json()) as { default_branch?: string };
    return typeof data.default_branch === "string" ? data.default_branch : "main";
  } catch {
    return "main";
  }
}

export async function fetchProjectFiles(
  owner: string,
  repo: string,
  branchHint?: string,
  subpath?: string
): Promise<ProjectFiles> {
  // Prefix every file path with the subpath if one was provided
  const filePath = (name: string) => (subpath ? `${subpath}/${name}` : name);

  // --- Try GitHub Contents API first ---
  // If a branch was specified in the URL, use it directly; otherwise let the
  // API pick the default branch by omitting the ref parameter.
  let packageJsonText: string | null = null;
  let packageLockText: string | null = null;

  const apiPath = branchHint
    ? `https://api.github.com/repos/${owner}/${repo}/contents/${filePath("package.json")}?ref=${branchHint}`
    : null;

  try {
    if (apiPath) {
      const res = await fetch(apiPath, { headers: GH_HEADERS });
      if (res.status === 403 || res.status === 401) {
        return { packageJson: null, packageLock: null, branch: null, error: "private" };
      }
      if (res.ok) {
        const data = (await res.json()) as ContentsApiResponse;
        if (data.encoding === "base64" && typeof data.content === "string") {
          packageJsonText = Buffer.from(
            data.content.replace(/\n/g, ""),
            "base64"
          ).toString("utf-8");
        }
      }
    } else {
      packageJsonText = await fetchViaContentsApi(owner, repo, filePath("package.json"));
    }
  } catch (err) {
    if (err instanceof Error && err.message === "private") {
      return { packageJson: null, packageLock: null, branch: null, error: "private" };
    }
  }

  // --- Fallback: raw URL with common branch names ---
  if (packageJsonText === null) {
    const defaultBranch = await getDefaultBranch(owner, repo);
    const candidates = [
      branchHint,
      defaultBranch,
      "main",
      "master",
      "develop",
      "trunk",
    ].filter((v): v is string => Boolean(v)).filter((v, i, arr) => arr.indexOf(v) === i);

    for (const b of candidates) {
      const raw = await fetchRawFallback(owner, repo, b, filePath("package.json"));
      if (raw) {
        try {
          const packageJson = JSON.parse(raw);
          const lockRaw = await fetchRawFallback(
            owner,
            repo,
            b,
            filePath("package-lock.json")
          );
          return {
            packageJson,
            packageLock: lockRaw ? JSON.parse(lockRaw) : null,
            branch: b,
          };
        } catch {
          continue;
        }
      }
    }

    return { packageJson: null, packageLock: null, branch: null, error: "no_package_json" };
  }

  // --- Parse result from Contents API ---
  let packageJson: unknown = null;
  try {
    packageJson = JSON.parse(packageJsonText);
  } catch {
    return { packageJson: null, packageLock: null, branch: null, error: "no_package_json" };
  }

  try {
    if (branchHint) {
      const lockRes = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/contents/${filePath("package-lock.json")}?ref=${branchHint}`,
        { headers: GH_HEADERS }
      );
      if (lockRes.ok) {
        const data = (await lockRes.json()) as ContentsApiResponse;
        if (data.encoding === "base64" && typeof data.content === "string") {
          packageLockText = Buffer.from(
            data.content.replace(/\n/g, ""),
            "base64"
          ).toString("utf-8");
        }
      }
    } else {
      packageLockText = await fetchViaContentsApi(
        owner,
        repo,
        filePath("package-lock.json")
      );
    }
  } catch {
    packageLockText = null;
  }

  let packageLock = null;
  if (packageLockText) {
    try {
      packageLock = JSON.parse(packageLockText);
    } catch {
      // malformed lock file — ignore
    }
  }

  return { packageJson, packageLock, branch: branchHint ?? null };
}
