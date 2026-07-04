// Gating-flow tests for `fixly guard` — the parser is covered in cli.test.ts;
// these cover what happens AFTER parsing: block aborts, --force overrides,
// caution requires --yes off-TTY, safe passes through, and the wrapped
// command's exit code propagates.

import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from "vitest";
import { EventEmitter } from "node:events";

const spawnMock = vi.hoisted(() => vi.fn());
const checkPackageMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", () => ({ spawn: spawnMock }));
vi.mock("@fixly/core", () => ({ checkPackage: checkPackageMock }));

import { guard } from "../src/commands/guard";

function fakeChild(exitCode: number): EventEmitter {
  const child = new EventEmitter();
  queueMicrotask(() => child.emit("close", exitCode));
  return child;
}

function verdictFor(
  name: string,
  verdict: "safe" | "caution" | "block",
  typosquatOf: string | null = null
) {
  return {
    package: name,
    evaluatedVersion: "1.0.0",
    verdict,
    reasons: [`${verdict} reason for ${name}`],
    warnings: [],
    summary: "",
    signals: { typosquatOf },
  };
}

let stderrSpy: MockInstance<typeof process.stderr.write>;
let originalIsTty: boolean;

beforeEach(() => {
  spawnMock.mockReset().mockImplementation(() => fakeChild(0));
  checkPackageMock.mockReset();
  stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  originalIsTty = process.stdin.isTTY;
  process.stdin.isTTY = false; // never let a test hang on the [y/N] prompt
});

afterEach(() => {
  stderrSpy.mockRestore();
  process.stdin.isTTY = originalIsTty;
});

function stderrText(): string {
  return stderrSpy.mock.calls.map((c) => String(c[0])).join("");
}

describe("guard gating flow", () => {
  it("passes a safe install through and propagates the exit code", async () => {
    checkPackageMock.mockResolvedValue(verdictFor("left-pad", "safe"));
    spawnMock.mockImplementation(() => fakeChild(3));
    const code = await guard({ argv: ["npm", "install", "left-pad"], yes: false, force: false });
    expect(code).toBe(3);
    expect(spawnMock).toHaveBeenCalledOnce();
    expect(String(spawnMock.mock.calls[0][0])).toContain("npm");
  });

  it("blocks the install (exit 2) without running the package manager", async () => {
    checkPackageMock.mockResolvedValue(verdictFor("lodahs", "block", "lodash"));
    const code = await guard({ argv: ["npm", "install", "lodahs"], yes: false, force: false });
    expect(code).toBe(2);
    expect(spawnMock).not.toHaveBeenCalled();
    expect(stderrText()).toContain("install blocked");
    expect(stderrText()).toContain("lodash"); // did-you-mean from typosquatOf
  });

  it("--force overrides a block and runs the install", async () => {
    checkPackageMock.mockResolvedValue(verdictFor("lodahs", "block", "lodash"));
    const code = await guard({ argv: ["npm", "install", "lodahs"], yes: false, force: true });
    expect(code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
    expect(stderrText()).toContain("overridden");
  });

  it("caution in a non-interactive session exits 1 without --yes", async () => {
    checkPackageMock.mockResolvedValue(verdictFor("newpkg", "caution"));
    const code = await guard({ argv: ["npm", "install", "newpkg"], yes: false, force: false });
    expect(code).toBe(1);
    expect(spawnMock).not.toHaveBeenCalled();
    expect(stderrText()).toContain("--yes");
  });

  it("--yes accepts caution verdicts and runs the install", async () => {
    checkPackageMock.mockResolvedValue(verdictFor("newpkg", "caution"));
    const code = await guard({ argv: ["npm", "install", "newpkg"], yes: true, force: false });
    expect(code).toBe(0);
    expect(spawnMock).toHaveBeenCalledOnce();
  });

  it("checks every named package and blocks on the worst verdict", async () => {
    checkPackageMock.mockImplementation(async (name: string) =>
      verdictFor(name, name === "lodahs" ? "block" : "safe")
    );
    const code = await guard({
      argv: ["npm", "install", "express", "lodahs"],
      yes: false,
      force: false,
    });
    expect(code).toBe(2);
    expect(checkPackageMock).toHaveBeenCalledTimes(2);
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("passes a bare lockfile install through without checking anything", async () => {
    const code = await guard({ argv: ["npm", "install"], yes: false, force: false });
    expect(code).toBe(0);
    expect(checkPackageMock).not.toHaveBeenCalled();
    expect(spawnMock).toHaveBeenCalledOnce();
    expect(stderrText()).toContain("vibecheck");
  });

  it("rejects a non-install command with a usage error", async () => {
    const code = await guard({ argv: ["npm", "run", "build"], yes: false, force: false });
    expect(code).toBe(2);
    expect(checkPackageMock).not.toHaveBeenCalled();
    expect(spawnMock).not.toHaveBeenCalled();
  });
});
