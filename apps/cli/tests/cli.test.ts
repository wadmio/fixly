import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parsePackageSpec } from "../src/commands/check";
import { scanLocalProject } from "../src/local";

describe("parsePackageSpec", () => {
  it("splits name and version", () => {
    expect(parsePackageSpec("lodash@4.17.21")).toEqual({ name: "lodash", version: "4.17.21" });
  });
  it("handles scoped packages", () => {
    expect(parsePackageSpec("@scope/pkg@1.0.0")).toEqual({ name: "@scope/pkg", version: "1.0.0" });
  });
  it("handles bare names, scoped and not", () => {
    expect(parsePackageSpec("lodash")).toEqual({ name: "lodash", version: null });
    expect(parsePackageSpec("@scope/pkg")).toEqual({ name: "@scope/pkg", version: null });
  });
});

describe("scanLocalProject", () => {
  let dir: string;
  afterEach(async () => {
    vi.unstubAllGlobals();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it("throws a friendly error for a non-npm directory", async () => {
    dir = await mkdtemp(join(tmpdir(), "fixly-empty-"));
    await expect(scanLocalProject(dir)).rejects.toThrow(/No package\.json/);
  });

  it("scans a local project through the shared pipeline", async () => {
    dir = await mkdtemp(join(tmpdir(), "fixly-proj-"));
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ name: "demo", dependencies: { "left-pad": "1.3.0" } })
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => ({
        status: 200,
        ok: true,
        json: async () => (url.includes("querybatch") ? { results: [{}] } : {}),
        text: async () => "",
      }))
    );
    const result = await scanLocalProject(dir);
    expect(result.error).toBeUndefined();
    expect(result.totalPackages).toBe(1);
    expect(result.target.filesMissing).toContain("package-lock.json");
  });
});
