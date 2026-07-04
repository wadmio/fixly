import { describe, it, expect, vi } from "vitest";
import { parseGitHubUrl } from "@fixly/core/url";

// NOTE: these are NOT page-render tests. They do not mount React or assert on
// rendered DOM — rendering React 19 under Vitest is currently broken in this
// toolchain (a react/react-dom dual-instance issue); Playwright E2E is the
// follow-up for render coverage. What this file covers:
//   1. the ScanForm module loads (compiles + its imports resolve)
//   2. the URL validation that gates navigation behaves correctly
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

describe("ScanForm module (loads, no DOM render)", () => {
  it("imports the component without throwing", async () => {
    const mod = await import("@/components/ScanForm");
    expect(typeof mod.default).toBe("function");
  });
});

describe("scan URL gate (ScanForm only navigates when this passes)", () => {
  it("accepts valid public repo URLs, including no-protocol and branch/subpath", () => {
    expect(parseGitHubUrl("https://github.com/owner/repo")).not.toBeNull();
    expect(parseGitHubUrl("github.com/owner/repo")).not.toBeNull();
    expect(
      parseGitHubUrl("https://github.com/owner/repo/tree/main/packages/web")
    ).not.toBeNull();
  });

  it("rejects invalid and non-GitHub URLs (form shows an error, no navigation)", () => {
    expect(parseGitHubUrl("not-a-url")).toBeNull();
    expect(parseGitHubUrl("https://gitlab.com/owner/repo")).toBeNull();
    expect(parseGitHubUrl("")).toBeNull();
  });
});
