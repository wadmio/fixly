// Pure GitHub URL parsing — no Node/network imports, safe to use in the browser
// (e.g. for client-side form validation in the web app).

export interface GitHubRepo {
  owner: string;
  repo: string;
  branch?: string;   // extracted from /tree/<branch>/...
  subpath?: string;  // extracted from /tree/<branch>/<subpath>
}

/**
 * Parse a GitHub repository URL into its parts, or return null if it is not a
 * recognizable public github.com repository URL.
 *
 * Accepts:
 *   https://github.com/owner/repo
 *   github.com/owner/repo            (protocol optional)
 *   https://github.com/owner/repo.git
 *   https://github.com/owner/repo/tree/<branch>
 *   https://github.com/owner/repo/tree/<branch>/<subpath...>
 */
export function parseGitHubUrl(url: string): GitHubRepo | null {
  if (typeof url !== "string" || url.trim() === "") return null;
  try {
    const trimmed = url.trim();
    const parsed = new URL(trimmed.startsWith("http") ? trimmed : `https://${trimmed}`);
    if (parsed.hostname !== "github.com" && parsed.hostname !== "www.github.com") {
      return null;
    }

    // pathname: /owner/repo[/tree/branch[/subpath...]]
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;

    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/, "");
    if (!owner || !repo) return null;

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
