import { describe, it, expect, vi, afterEach } from "vitest";
import { queryOsvBatch, osvQueryKey } from "../src/osv";

function jsonRes(status: number, body: unknown) {
  return { status, ok: status >= 200 && status < 300, json: async () => body, text: async () => JSON.stringify(body) };
}

afterEach(() => vi.unstubAllGlobals());

describe("queryOsvBatch", () => {
  it("aligns querybatch results to the input queries and fetches details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith("/querybatch")) {
          const body = JSON.parse(String(init?.body));
          // Second query (idx 1) is the vulnerable one — verify alignment.
          const results = body.queries.map((_: unknown, i: number) =>
            i === 1 ? { vulns: [{ id: "GHSA-aaaa" }] } : {}
          );
          return jsonRes(200, { results });
        }
        if (url.includes("/vulns/GHSA-aaaa")) {
          return jsonRes(200, { id: "GHSA-aaaa", summary: "boom" });
        }
        return jsonRes(404, {});
      })
    );

    const queries = [
      { name: "safe-pkg", version: "1.0.0" },
      { name: "vuln-pkg", version: "2.0.0" },
    ];
    const { results } = await queryOsvBatch(queries);
    expect(results.has(osvQueryKey({ name: "safe-pkg", version: "1.0.0" }))).toBe(false);
    expect(results.get(osvQueryKey({ name: "vuln-pkg", version: "2.0.0" }))?.[0].id).toBe("GHSA-aaaa");
  });

  it("follows next_page_token so heavily-affected packages don't lose advisories", async () => {
    let page = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.endsWith("/querybatch")) {
          const body = JSON.parse(String(init?.body));
          const hasToken = body.queries[0].page_token !== undefined;
          if (!hasToken) {
            page++;
            return jsonRes(200, { results: [{ vulns: [{ id: "GHSA-1" }], next_page_token: "tok" }] });
          }
          return jsonRes(200, { results: [{ vulns: [{ id: "GHSA-2" }] }] }); // last page, no token
        }
        const id = url.split("/vulns/")[1];
        return jsonRes(200, { id, summary: id });
      })
    );

    const { results } = await queryOsvBatch([{ name: "big-pkg", version: "1.0.0" }]);
    const ids = results.get(osvQueryKey({ name: "big-pkg", version: "1.0.0" }))?.map((v) => v.id).sort();
    expect(ids).toEqual(["GHSA-1", "GHSA-2"]); // both pages collected
    expect(page).toBe(1);
  });
});
