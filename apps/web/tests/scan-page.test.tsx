import { describe, it, expect, vi } from "vitest";
import { parseGitHubUrl } from "@fixly/core/url";

// Smoke tests for the scan page. Full DOM-render tests (React Testing Library)
// are intentionally not run here: rendering React 19 under Vitest is currently
// broken in this toolchain (a known react/react-dom dual-instance issue). The
// proper place for page-render coverage is a Playwright E2E job — tracked as a
// follow-up. These tests still verify that the scan page's interactive module
// loads and that the URL gate driving navigation behaves correctly.
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

describe("scan page (ScanForm)", () => {
  it("loads the scan form component module without throwing", async () => {
    const mod = await import("@/components/ScanForm");
    expect(typeof mod.default).toBe("function");
  });

  describe("URL gate (handleSubmit only navigates when this passes)", () => {
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
});
