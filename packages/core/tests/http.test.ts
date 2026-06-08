import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchWithRetry, mapWithConcurrency } from "../src/http";

function res(status: number) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("fetchWithRetry", () => {
  it("retries a transient 503 then returns the eventual success", async () => {
    const f = vi
      .fn()
      .mockResolvedValueOnce(res(503))
      .mockResolvedValueOnce(res(200));
    vi.stubGlobal("fetch", f);
    const r = await fetchWithRetry("http://x", undefined, { baseDelayMs: 0 });
    expect(r.status).toBe(200);
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("gives up after the retry budget and returns the last response", async () => {
    const f = vi.fn().mockResolvedValue(res(503));
    vi.stubGlobal("fetch", f);
    const r = await fetchWithRetry("http://x", undefined, { retries: 2, baseDelayMs: 0 });
    expect(r.status).toBe(503);
    expect(f).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it("retries a thrown network error then succeeds", async () => {
    const f = vi
      .fn()
      .mockRejectedValueOnce(new Error("ECONNRESET"))
      .mockResolvedValueOnce(res(200));
    vi.stubGlobal("fetch", f);
    const r = await fetchWithRetry("http://x", undefined, { baseDelayMs: 0 });
    expect(r.status).toBe(200);
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("does not retry a definitive 404", async () => {
    const f = vi.fn().mockResolvedValue(res(404));
    vi.stubGlobal("fetch", f);
    const r = await fetchWithRetry("http://x", undefined, { baseDelayMs: 0 });
    expect(r.status).toBe(404);
    expect(f).toHaveBeenCalledTimes(1);
  });
});

describe("mapWithConcurrency", () => {
  it("preserves input order and never exceeds the limit", async () => {
    let active = 0;
    let maxActive = 0;
    const items = [1, 2, 3, 4, 5, 6, 7, 8];
    const out = await mapWithConcurrency(items, 3, async (n) => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return n * 2;
    });
    expect(out).toEqual(items.map((n) => n * 2));
    expect(maxActive).toBeLessThanOrEqual(3);
  });
});
