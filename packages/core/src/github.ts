import type { ScanErrorCode } from "./types";

export type { GitHubRepo } from "./github-url";

const GH_API = "https://api.github.com";

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "fixly-scanner/1.0",
  };
  // Server-side only — this module is never imported by client code.
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export type FetchErrorCode = Extract<
  ScanErrorCode,
  "repo_not_found" | "private_repo" | "branch_not_found" | "no_package_json" | "rate_limited" | "github_error"
>;

export interface FetchedProject {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageJson: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  packageLock: any | null;
  branch: string;
  filesFound: string[];
  filesMissing: string[];
}

export type FetchResult =
  | { ok: true; project: FetchedProject }
  | { ok: false; code: FetchErrorCode; message: string };

const RATE_LIMIT_MESSAGE =
  "GitHub API rate limit reached. Set a GITHUB_TOKEN environment variable on the server to raise the limit (see docs/development.md), then try again.";

interface GhResponse {
  status: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: any;
}

async function ghGet(path: string): Promise<GhResponse> {
  const res = await fetch(`${GH_API}${path}`, { headers: authHeaders() });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

function isRateLimited(res: GhResponse): boolean {
  return (
    (res.status === 403 || res.status === 429) &&
    typeof res.body?.message === "string" &&
    /rate limit/i.test(res.body.message)
  );
}

type FileResult =
  | { kind: "found"; content: string }
  | { kind: "missing" }
  | { kind: "rate_limited" }
  | { kind: "error"; message: string };

async function getFileContent(
  owner: string,
  repo: string,
  filePath: string,
  ref: string
): Promise<FileResult> {
  const res = await ghGet(
    `/repos/${owner}/${repo}/contents/${filePath}?ref=${encodeURIComponent(ref)}`
  );
  if (res.status === 404) return { kind: "missing" };
  if (isRateLimited(res)) return { kind: "rate_limited" };
  if (res.status === 401 || res.status === 403) {
    return { kind: "error", message: "Access to the file was forbidden." };
  }
  if (res.status !== 200) {
    return { kind: "error", message: `GitHub API error (${res.status}).` };
  }
  if (res.body?.encoding === "base64" && typeof res.body.content === "string") {
    return {
      kind: "found",
      content: Buffer.from(res.body.content.replace(/\n/g, ""), "base64").toString("utf-8"),
    };
  }
  return { kind: "error", message: "Unexpected GitHub response while reading a file." };
}

/**
 * Locate and download package.json (+ optional package-lock.json) for a public
 * repository. The repo and branch are verified up front so callers receive a
 * precise {@link FetchErrorCode} instead of a generic "not found".
 */
export async function fetchProject(
  owner: string,
  repo: string,
  branchHint?: string,
  subpath?: string
): Promise<FetchResult> {
  // 1. Repo existence / access + default branch.
  const repoRes = await ghGet(`/repos/${owner}/${repo}`);
  if (isRateLimited(repoRes)) return { ok: false, code: "rate_limited", message: RATE_LIMIT_MESSAGE };
  if (repoRes.status === 404) {
    return {
      ok: false,
      code: "repo_not_found",
      message: `Repository ${owner}/${repo} was not found. Check the URL — it may not exist, or it may be private (only public repositories are supported).`,
    };
  }
  if (repoRes.status === 401 || repoRes.status === 403) {
    return {
      ok: false,
      code: "private_repo",
      message: `Access to ${owner}/${repo} is forbidden. Only public repositories are supported.`,
    };
  }
  if (repoRes.status !== 200) {
    return { ok: false, code: "github_error", message: `GitHub API error (${repoRes.status}) reading ${owner}/${repo}.` };
  }
  const defaultBranch =
    typeof repoRes.body?.default_branch === "string" ? repoRes.body.default_branch : "main";

  // 2. Resolve branch (verify it exists if the URL specified one).
  let branch = defaultBranch;
  if (branchHint) {
    const branchRes = await ghGet(
      `/repos/${owner}/${repo}/branches/${encodeURIComponent(branchHint)}`
    );
    if (isRateLimited(branchRes)) return { ok: false, code: "rate_limited", message: RATE_LIMIT_MESSAGE };
    if (branchRes.status === 404) {
      return { ok: false, code: "branch_not_found", message: `Branch "${branchHint}" was not found in ${owner}/${repo}.` };
    }
    if (branchRes.status !== 200) {
      return { ok: false, code: "github_error", message: `GitHub API error (${branchRes.status}) reading branch "${branchHint}".` };
    }
    branch = branchHint;
  }

  const dir = subpath ? `${subpath.replace(/^\/+|\/+$/g, "")}/` : "";
  const where = subpath ? ` in subfolder "${subpath}"` : "";

  // 3. package.json (required).
  const pkg = await getFileContent(owner, repo, `${dir}package.json`, branch);
  if (pkg.kind === "rate_limited") return { ok: false, code: "rate_limited", message: RATE_LIMIT_MESSAGE };
  if (pkg.kind === "error") return { ok: false, code: "github_error", message: pkg.message };
  if (pkg.kind === "missing") {
    return {
      ok: false,
      code: "no_package_json",
      message: `No package.json found in ${owner}/${repo}${where} on branch "${branch}". This may not be a Node.js project, or the file may be in a different folder.`,
    };
  }
  let packageJson: unknown;
  try {
    packageJson = JSON.parse(pkg.content);
  } catch {
    return { ok: false, code: "no_package_json", message: `The package.json in ${owner}/${repo} could not be parsed as JSON.` };
  }

  // 4. package-lock.json (optional).
  const filesFound = ["package.json"];
  const filesMissing: string[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let packageLock: any = null;
  const lock = await getFileContent(owner, repo, `${dir}package-lock.json`, branch);
  if (lock.kind === "found") {
    try {
      packageLock = JSON.parse(lock.content);
      filesFound.push("package-lock.json");
    } catch {
      filesMissing.push("package-lock.json");
    }
  } else {
    filesMissing.push("package-lock.json");
  }

  return { ok: true, project: { packageJson, packageLock, branch, filesFound, filesMissing } };
}
