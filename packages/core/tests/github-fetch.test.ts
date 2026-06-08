import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchProject } from "../src/github";

function jsonRes(status: number, body: unknown) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  };
}

function b64(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf-8").toString("base64");
}

afterEach(() => vi.unstubAllGlobals());

describe("fetchProject — structured error codes", () => {
  it("repo_not_found when repo metadata is 404", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonRes(404, { message: "Not Found" })));
    expect(await fetchProject("o", "r")).toMatchObject({ ok: false, code: "repo_not_found" });
  });

  it("private_repo on 403 without a rate-limit message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonRes(403, { message: "Forbidden" })));
    expect(await fetchProject("o", "r")).toMatchObject({ ok: false, code: "private_repo" });
  });

  it("rate_limited on 403 with a rate-limit message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonRes(403, { message: "API rate limit exceeded for 1.2.3.4" }))
    );
    expect(await fetchProject("o", "r")).toMatchObject({ ok: false, code: "rate_limited" });
  });

  it("branch_not_found when a requested branch 404s", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("/repos/o/r")) return jsonRes(200, { default_branch: "main" });
        if (url.includes("/branches/")) return jsonRes(404, { message: "Branch not found" });
        return jsonRes(200, {});
      })
    );
    expect(await fetchProject("o", "r", "missing-branch")).toMatchObject({
      ok: false,
      code: "branch_not_found",
    });
  });

  it("no_package_json when package.json is missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("/repos/o/r")) return jsonRes(200, { default_branch: "main" });
        if (url.includes("/contents/package.json")) return jsonRes(404, { message: "Not Found" });
        return jsonRes(200, {});
      })
    );
    expect(await fetchProject("o", "r")).toMatchObject({ ok: false, code: "no_package_json" });
  });
});

describe("fetchProject — success", () => {
  it("returns parsed files and records found/missing", async () => {
    const pkg = { name: "demo", dependencies: { "left-pad": "^1.3.0" } };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("/repos/o/r")) return jsonRes(200, { default_branch: "main" });
        if (url.includes("/contents/package.json"))
          return jsonRes(200, { encoding: "base64", content: b64(pkg) });
        if (url.includes("/contents/package-lock.json"))
          return jsonRes(404, { message: "Not Found" });
        return jsonRes(200, {});
      })
    );
    const r = await fetchProject("o", "r");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.project.branch).toBe("main");
      expect(r.project.packageJson.name).toBe("demo");
      expect(r.project.filesFound).toContain("package.json");
      expect(r.project.filesMissing).toContain("package-lock.json");
    }
  });
});
