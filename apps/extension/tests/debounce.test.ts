import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { debounce } from "../src/debounce";

describe("debounce", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("runs the callback once after the quiet period", () => {
    const fn = vi.fn();
    const d = debounce(fn, 1500);

    d("a");
    expect(fn).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1499);
    expect(fn).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("coalesces rapid calls and fires with the latest arguments", () => {
    const fn = vi.fn();
    const d = debounce(fn, 1500);

    d("first");
    vi.advanceTimersByTime(500);
    d("second");
    vi.advanceTimersByTime(500);
    d("third"); // each call resets the 1500ms timer

    vi.advanceTimersByTime(1500);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenCalledWith("third");
  });

  it("cancel() drops a pending invocation", () => {
    const fn = vi.fn();
    const d = debounce(fn, 1500);

    d("x");
    d.cancel();
    vi.advanceTimersByTime(5000);
    expect(fn).not.toHaveBeenCalled();
  });

  it("allows a fresh call after firing", () => {
    const fn = vi.fn();
    const d = debounce(fn, 1000);

    d("one");
    vi.advanceTimersByTime(1000);
    d("two");
    vi.advanceTimersByTime(1000);

    expect(fn).toHaveBeenCalledTimes(2);
    expect(fn).toHaveBeenNthCalledWith(1, "one");
    expect(fn).toHaveBeenNthCalledWith(2, "two");
  });
});
