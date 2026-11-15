export class BoundedQueue<T> implements AsyncIterableIterator<T> {
  private readonly items: T[] = [];
  private readonly readers: {
    readonly resolve: (result: IteratorResult<T>) => void;
    readonly reject: (error: Error) => void;
  }[] = [];
  private readonly writers: {
    readonly value: T;
    readonly resolve: () => void;
    readonly reject: (error: Error) => void;
    readonly cleanup: () => void;
  }[] = [];
  private closed = false;
  private failure: Error | undefined;

  constructor(readonly highWaterMark: number) {
    if (!Number.isSafeInteger(highWaterMark) || highWaterMark < 1) {
      throw new RangeError("highWaterMark must be a positive safe integer");
    }
  }

  get size(): number {
    return this.items.length;
  }

  async push(value: T, signal?: AbortSignal): Promise<void> {
    throwIfAborted(signal);
    if (this.closed) throw this.failure ?? new Error("queue is closed");

    const reader = this.readers.shift();
    if (reader !== undefined) {
      reader.resolve({ value, done: false });
      return;
    }
    if (this.items.length < this.highWaterMark) {
      this.items.push(value);
      return;
    }

    await new Promise<void>((resolve, reject) => {
      let abortHandler: (() => void) | undefined;
      const cleanup = (): void => {
        if (abortHandler !== undefined && signal !== undefined) {
          signal.removeEventListener("abort", abortHandler);
        }
      };
      const writer = {
        value,
        resolve: (): void => {
          cleanup();
          resolve();
        },
        reject: (error: Error): void => {
          cleanup();
          reject(error);
        },
        cleanup,
      };
      if (signal !== undefined) {
        abortHandler = (): void => {
          const index = this.writers.indexOf(writer);
          if (index >= 0) this.writers.splice(index, 1);
          writer.reject(abortError());
        };
        signal.addEventListener("abort", abortHandler, { once: true });
      }
      this.writers.push(writer);
      if (signal?.aborted === true) abortHandler?.();
    });
  }

  async next(): Promise<IteratorResult<T>> {
    if (this.items.length > 0) {
      const value = this.items.shift() as T;
      this.admitWriter();
      return { value, done: false };
    }

    const writer = this.writers.shift();
    if (writer !== undefined) {
      writer.resolve();
      return { value: writer.value, done: false };
    }
    if (this.closed) {
      if (this.failure !== undefined) throw this.failure;
      return { value: undefined, done: true };
    }
    return new Promise<IteratorResult<T>>((resolve, reject) => {
      this.readers.push({ resolve, reject });
    });
  }

  close(error?: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.failure = error;
    for (const writer of this.writers.splice(0)) {
      writer.cleanup();
      writer.reject(error ?? new Error("queue is closed"));
    }
    if (this.items.length === 0) this.finishReaders();
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<T> {
    return this;
  }

  return(): Promise<IteratorResult<T>> {
    this.close();
    return Promise.resolve({ value: undefined, done: true });
  }

  private admitWriter(): void {
    if (this.closed) return;
    const writer = this.writers.shift();
    if (writer === undefined) return;
    const reader = this.readers.shift();
    if (reader !== undefined) {
      reader.resolve({ value: writer.value, done: false });
    } else {
      this.items.push(writer.value);
    }
    writer.resolve();
  }

  private finishReaders(): void {
    for (const reader of this.readers.splice(0)) {
      if (this.failure !== undefined) {
        reader.reject(this.failure);
      } else {
        reader.resolve({ value: undefined, done: true });
      }
    }
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw abortError();
}

function abortError(): Error {
  const error = new Error("queue operation was aborted");
  error.name = "AbortError";
  return error;
}
