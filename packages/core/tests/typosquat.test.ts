import { describe, it, expect } from "vitest";
import { editDistance, findTyposquatTarget } from "../src/typosquat";

describe("editDistance", () => {
  it("counts insert/delete/substitute/transpose as 1 each", () => {
    expect(editDistance("lodash", "lodash")).toBe(0);
    expect(editDistance("lodash", "lodahs")).toBe(1); // transposition
    expect(editDistance("lodash", "lodas")).toBe(1); // deletion
    expect(editDistance("lodash", "lodashh")).toBe(1); // insertion
    expect(editDistance("lodash", "lodesh")).toBe(1); // substitution
    expect(editDistance("react", "vue")).toBeGreaterThan(2);
  });
});

describe("findTyposquatTarget", () => {
  it("flags classic one-character typos of popular packages", () => {
    expect(findTyposquatTarget("lodahs")?.target).toBe("lodash");
    expect(findTyposquatTarget("expresss")?.target).toBe("express");
    expect(findTyposquatTarget("axois")?.target).toBe("axios");
  });

  it("flags separator confusion (same letters, different separators)", () => {
    expect(findTyposquatTarget("fastglob")?.target).toBe("fast-glob");
    expect(findTyposquatTarget("node.fetch")?.target).toBe("node-fetch");
  });

  it("flags the documented slopsquat pattern: dropped plugin prefix", () => {
    // Real-world case: AIs hallucinate "unused-imports" instead of
    // "eslint-plugin-unused-imports".
    const match = findTyposquatTarget("unused-imports");
    expect(match?.target).toBe("eslint-plugin-unused-imports");
    expect(match?.kind).toBe("affix");
  });

  it("never flags the popular packages themselves", () => {
    expect(findTyposquatTarget("lodash")).toBeNull();
    expect(findTyposquatTarget("react")).toBeNull();
    expect(findTyposquatTarget("express")).toBeNull();
  });

  it("does not flag clearly distinct names", () => {
    expect(findTyposquatTarget("my-cool-internal-thing")).toBeNull();
    expect(findTyposquatTarget("@myorg/design-tokens")).toBeNull();
  });

  it("does not flag scoped packages that merely share a tail with a differently-scoped popular one", () => {
    // Regression: "@types/node" and "@vercel/node" both reduce to "node" once
    // the scope is stripped — but they are NOT typosquats of each other.
    expect(findTyposquatTarget("@types/node")).toBeNull();
    expect(findTyposquatTarget("@types/react")).toBeNull();
    expect(findTyposquatTarget("@types/express")).toBeNull();
  });
});
