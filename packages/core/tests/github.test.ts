import { describe, it, expect } from "vitest";
import { parseGitHubUrl } from "../src/github-url";

describe("parseGitHubUrl", () => {
  it("parses a plain owner/repo URL", () => {
    expect(parseGitHubUrl("https://github.com/owner/repo")).toEqual({
      owner: "owner",
      repo: "repo",
    });
  });

  it("accepts a URL without a protocol", () => {
    expect(parseGitHubUrl("github.com/owner/repo")).toEqual({
      owner: "owner",
      repo: "repo",
    });
  });

  it("strips a trailing .git suffix", () => {
    expect(parseGitHubUrl("https://github.com/owner/repo.git")).toEqual({
      owner: "owner",
      repo: "repo",
    });
  });

  it("extracts a branch from a /tree/<branch> URL", () => {
    expect(parseGitHubUrl("https://github.com/owner/repo/tree/main")).toEqual({
      owner: "owner",
      repo: "repo",
      branch: "main",
    });
  });

  it("extracts branch and subpath from a /tree/<branch>/<subpath> URL", () => {
    expect(
      parseGitHubUrl("https://github.com/owner/repo/tree/main/packages/web")
    ).toEqual({
      owner: "owner",
      repo: "repo",
      branch: "main",
      subpath: "packages/web",
    });
  });

  it.each([
    "https://gitlab.com/owner/repo",
    "https://github.com/owner",
    "not a url",
    "",
  ])("rejects invalid input: %s", (input) => {
    expect(parseGitHubUrl(input)).toBeNull();
  });
});
