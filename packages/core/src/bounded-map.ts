// A Map with a maximum entry count — a memory backstop for the long-lived,
// module-level caches (NVD, EPSS, registry, scan results). When full, inserting
// a new key evicts the oldest (insertion-order / FIFO). Re-setting an existing
// key refreshes its recency, giving a light LRU flavor without the bookkeeping.
// Not a precise LRU; the point is simply that these caches can't grow forever
// in a long-running server process.

export class BoundedMap<K, V> {
  private readonly map = new Map<K, V>();

  constructor(private readonly maxEntries: number) {
    if (maxEntries < 1) throw new Error("BoundedMap maxEntries must be >= 1");
  }

  get(key: K): V | undefined {
    return this.map.get(key);
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) {
      this.map.delete(key); // refresh recency
    } else if (this.map.size >= this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    this.map.set(key, value);
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}
