import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parsePackageSpec } from "../src/commands/check";
import { parseInstallCommand } from "../src/commands/guard";
import { parseGuardArgs } from "../src/cli";
import { gradeFailsThreshold } from "../src/commands/vibecheck";
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

describe("parseInstallCommand", () => {
  it("recognizes npm/pnpm/yarn/bun install and add", () => {
    expect(parseInstallCommand(["npm", "install", "lodash"])?.specs).toEqual(["lodash"]);
    expect(parseInstallCommand(["pnpm", "add", "-D", "vitest"])?.specs).toEqual(["vitest"]);
    expect(parseInstallCommand(["yarn", "add", "react", "react-dom"])?.specs).toEqual([
      "react",
      "react-dom",
    ]);
    expect(parseInstallCommand(["bun", "i", "zod@3.25.0"])?.specs).toEqual(["zod@3.25.0"]);
  });

  it("rejects non-install commands and unknown binaries", () => {
    expect(parseInstallCommand(["npm", "run", "build"])).toBeNull();
    expect(parseInstallCommand(["make", "install"])).toBeNull();
    expect(parseInstallCommand([])).toBeNull();
  });

  it("passes flags through and separates uncheckable specs", () => {
    const parsed = parseInstallCommand([
      "npm",
      "install",
      "--save-dev",
      "lodash",
      "git+https://github.com/x/y.git",
      "file:../local-pkg",
      "./relative",
    ]);
    expect(parsed?.specs).toEqual(["lodash"]);
    expect(parsed?.uncheckable).toEqual([
      "git+https://github.com/x/y.git",
      "file:../local-pkg",
      "./relative",
    ]);
    expect(parsed?.args).toContain("--save-dev");
  });

  it("treats a bare lockfile install as having no specs", () => {
    expect(parseInstallCommand(["npm", "install"])?.specs).toEqual([]);
  });

  it("does not treat a value-taking flag's value as a package", () => {
    // pnpm --filter <ws> and npm -w <ws> name a workspace, not a package.
    expect(parseInstallCommand(["pnpm", "add", "--filter", "web", "lodash"])?.specs).toEqual([
      "lodash",
    ]);
    expect(parseInstallCommand(["npm", "i", "-w", "myworkspace", "lodash"])?.specs).toEqual([
      "lodash",
    ]);
    // Equals form is self-contained.
    expect(parseInstallCommand(["pnpm", "add", "--filter=web", "lodash"])?.specs).toEqual([
      "lodash",
    ]);
  });

  it("treats pnpm -w as a boolean (still checks the package after it)", () => {
    // -w is --workspace-root on pnpm, not a value flag — lodash must be checked.
    expect(parseInstallCommand(["pnpm", "add", "-w", "lodash"])?.specs).toEqual(["lodash"]);
  });

  it("handles `yarn global add`", () => {
    const parsed = parseInstallCommand(["yarn", "global", "add", "typescript"]);
    expect(parsed?.specs).toEqual(["typescript"]);
    expect(parsed?.args).toEqual(["global", "add", "typescript"]);
  });
});

describe("parseGuardArgs", () => {
  it("does NOT treat the wrapped command's --force as fixly's block-override", () => {
    // The security bug: `npm install --force` must not disarm guard's BLOCK.
    const { argv, force, yes } = parseGuardArgs(["--", "npm", "install", "--force", "lodahs"]);
    expect(force).toBe(false);
    expect(yes).toBe(false);
    expect(argv).toEqual(["npm", "install", "--force", "lodahs"]);
  });

  it("honors fixly's --force/--yes when placed before the separator", () => {
    const { argv, force, yes } = parseGuardArgs(["--force", "--yes", "--", "npm", "install", "x"]);
    expect(force).toBe(true);
    expect(yes).toBe(true);
    expect(argv).toEqual(["npm", "install", "x"]);
  });

  it("passes a clean wrapped install through with no fixly flags set", () => {
    const { argv, force, yes } = parseGuardArgs(["--", "pnpm", "add", "-D", "vitest"]);
    expect(force).toBe(false);
    expect(yes).toBe(false);
    expect(argv).toEqual(["pnpm", "add", "-D", "vitest"]);
  });

  it("supports the legacy no-separator form (fixly flags stripped from argv)", () => {
    const { argv, force } = parseGuardArgs(["--force", "npm", "install", "x"]);
    expect(force).toBe(true);
    expect(argv).toEqual(["npm", "install", "x"]);
  });
});

describe("gradeFailsThreshold", () => {
  it("fails when the grade ranks below the threshold", () => {
    expect(gradeFailsThreshold("C", "B")).toBe(true);
    expect(gradeFailsThreshold("F", "A")).toBe(true);
    expect(gradeFailsThreshold("D", "C")).toBe(true);
  });
  it("passes when the grade meets or beats the threshold", () => {
    expect(gradeFailsThreshold("B", "B")).toBe(false);
    expect(gradeFailsThreshold("A", "C")).toBe(false);
    expect(gradeFailsThreshold("A", "A")).toBe(false);
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
