// Network reliability helpers shared by the GitHub and OSV clients.

export interface RetryOptions {
  /** Number of retries after the first attempt (default 3 → up to 4 tries). */
  retries?: number;
  /** Base backoff delay in ms (default 300). */
  baseDelayMs?: number;
  /** Maximum backoff delay in ms (default 4000). */
  maxDelayMs?: number;
}

// Transient statuses worth retrying. 403/404 are definitive (auth, rate limit,
// missing) and are handled by callers, not retried here.
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffDelay(attempt: number, base: number, max: number): number {
  const expo = Math.min(base * 2 ** attempt, max);
  // Full jitter on the top 25% to avoid thundering-herd retries.
  return expo + Math.random() * (expo * 0.25);
}

function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (!Number.isNaN(seconds)) return Math.min(seconds * 1000, 10_000);
  const date = Date.parse(value);
  if (!Number.isNaN(date)) return Math.max(0, Math.min(date - Date.now(), 10_000));
  return null;
}

function retryAfterMs(res: Response): number | null {
  // Guard for mocked responses in tests that may lack a real Headers object.
  if (res.headers && typeof res.headers.get === "function") {
    return parseRetryAfter(res.headers.get("retry-after"));
  }
  return null;
}

/**
 * fetch() with exponential backoff + jitter on transient failures (network
 * errors and retryable status codes). Honors `Retry-After` when present.
 */
export async function fetchWithRetry(
  url: string,
  init?: RequestInit,
  opts: RetryOptions = {}
): Promise<Response> {
  const retries = opts.retries ?? 3;
  const base = opts.baseDelayMs ?? 300;
  const max = opts.maxDelayMs ?? 4000;

  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, init);
      if (!RETRYABLE_STATUS.has(res.status) || attempt === retries) return res;
      await sleep(retryAfterMs(res) ?? backoffDelay(attempt, base, max));
    } catch (err) {
      lastError = err;
      if (attempt === retries) throw err;
      await sleep(backoffDelay(attempt, base, max));
    }
  }
  // Unreachable: the loop either returns or throws.
  throw lastError instanceof Error ? lastError : new Error("fetch failed");
}

/**
 * Run an async mapper over items with a bounded number of concurrent workers,
 * preserving input order in the result. Used to cap parallel OSV detail calls.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index], index);
    }
  }

  const workerCount = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}
