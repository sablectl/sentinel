export interface RateLimitOptions {
  readonly limit: number;
  readonly windowMs: number;
  readonly maximumKeys?: number;
}

interface Counter {
  start: number;
  count: number;
}

export class RateLimiter {
  private readonly counters = new Map<string, Counter>();
  private readonly maximumKeys: number;

  constructor(private readonly options: RateLimitOptions) {
    this.maximumKeys = options.maximumKeys ?? 4_096;
    if (
      !Number.isSafeInteger(options.limit) ||
      options.limit < 1 ||
      !Number.isSafeInteger(options.windowMs) ||
      options.windowMs < 1 ||
      !Number.isSafeInteger(this.maximumKeys) ||
      this.maximumKeys < 1
    ) {
      throw new RangeError("rate limit options must be positive safe integers");
    }
  }

  consume(key: string, now = Date.now()): boolean {
    if (key.length === 0 || !Number.isSafeInteger(now) || now < 0) return false;
    const current = this.counters.get(key);
    if (current !== undefined && now - current.start < this.options.windowMs) {
      if (current.count >= this.options.limit) return false;
      current.count += 1;
      return true;
    }

    if (current !== undefined) this.counters.delete(key);
    this.removeExpired(now);
    if (this.counters.size >= this.maximumKeys) return false;
    this.counters.set(key, { start: now, count: 1 });
    return true;
  }

  get trackedKeys(): number {
    return this.counters.size;
  }

  private removeExpired(now: number): void {
    for (const [key, counter] of this.counters) {
      if (now - counter.start >= this.options.windowMs) {
        this.counters.delete(key);
      }
    }
  }
}
