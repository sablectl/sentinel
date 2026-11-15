import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import type {
  Checkpoint,
  CheckpointRepository,
  RawRecord,
  SourceReader,
  SourceType,
} from "../types.js";
import { checkpointIsStale } from "./rotation.js";

const CHECKPOINT_HASH_BYTES = 64;

export interface FileTailReaderOptions {
  readonly name: string;
  readonly sourceType: SourceType;
  readonly path: string;
  readonly checkpoints: CheckpointRepository;
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
  readonly chunkBytes?: number;
  readonly separator?: "line" | "blank-line";
}

export class FileTooLargeError extends Error {
  readonly size: number;
  readonly limit: number;

  constructor(size: number, limit: number) {
    super(
      `source file is ${size} bytes, above the configured limit of ${limit} bytes`,
    );
    this.name = "FileTooLargeError";
    this.size = size;
    this.limit = limit;
  }
}

export class FileTailReader implements SourceReader {
  readonly name: string;
  readonly sourceType: SourceType;
  readonly path: string;

  private readonly checkpoints: CheckpointRepository;
  private readonly maxRecordBytes: number;
  private readonly maxFileBytes: number;
  private readonly chunkBytes: number;
  private readonly separator: "line" | "blank-line";
  private currentCheckpoint: Checkpoint;
  private activeFile: {
    readonly inode: string;
    readonly size: number;
    readonly fileId: string;
  } | null = null;
  private reading = false;

  constructor(options: FileTailReaderOptions) {
    if (
      options.name.length === 0 ||
      options.name.length > 128 ||
      /\p{Cc}/u.test(options.name)
    ) {
      throw new RangeError(
        "source name must contain between 1 and 128 characters",
      );
    }
    if (
      !Number.isSafeInteger(options.maxRecordBytes) ||
      options.maxRecordBytes < 1 ||
      !Number.isSafeInteger(options.maxFileBytes) ||
      options.maxFileBytes < options.maxRecordBytes
    ) {
      throw new RangeError(
        "file and record limits must be positive safe integers",
      );
    }

    this.name = options.name;
    this.sourceType = options.sourceType;
    this.path = options.path;
    this.checkpoints = options.checkpoints;
    this.maxRecordBytes = options.maxRecordBytes;
    this.maxFileBytes = options.maxFileBytes;
    this.chunkBytes = options.chunkBytes ?? 64 * 1024;
    this.separator = options.separator ?? "line";
    if (!Number.isSafeInteger(this.chunkBytes) || this.chunkBytes < 1) {
      throw new RangeError("chunkBytes must be a positive safe integer");
    }
    this.currentCheckpoint = {
      path: this.path,
      inode: "",
      size: 0,
      offset: 0,
      lineNumber: 0,
      lastHash: null,
    };
    this.checkpoints.registerSource(this);
  }

  checkpoint(): Checkpoint {
    return this.currentCheckpoint;
  }

  commit(record: RawRecord): void {
    const active = this.activeFile;
    if (
      !this.reading ||
      active === null ||
      record.source !== this.name ||
      record.sourceType !== this.sourceType ||
      record.fileId !== active.fileId ||
      record.offset !== this.currentCheckpoint.offset ||
      record.lineNumber !== this.currentCheckpoint.lineNumber + 1 ||
      record.nextOffset <= record.offset
    ) {
      throw new Error("record does not match the reader checkpoint");
    }

    const checkpoint: Checkpoint = {
      path: this.path,
      inode: active.inode,
      size: active.size,
      offset: record.nextOffset,
      lineNumber: record.nextLineNumber,
      lastHash: record.checkpointHash,
    };
    this.checkpoints.save(this.name, checkpoint);
    this.currentCheckpoint = checkpoint;
  }

  async *read(signal: AbortSignal): AsyncIterable<RawRecord> {
    if (this.reading)
      throw new Error("source reader already has an active read");
    this.reading = true;
    let handle: FileHandle | undefined;
    try {
      throwIfAborted(signal);
      handle = await open(
        this.path,
        fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK,
      );
      const info = await handle.stat();
      if (!info.isFile()) throw new Error("source path is not a regular file");
      if (info.size > this.maxFileBytes) {
        throw new FileTooLargeError(info.size, this.maxFileBytes);
      }

      const inode = `${String(info.dev)}:${String(info.ino)}`;
      const fileId = inode;
      this.checkpoints.registerSource(this);
      const stored = this.checkpoints.load(this.name);
      const observedHash =
        stored !== null && stored.offset > 0 && stored.offset <= info.size
          ? await hashTail(handle, stored.offset)
          : null;
      const initial: Checkpoint = {
        path: this.path,
        inode,
        size: info.size,
        offset: 0,
        lineNumber: 0,
        lastHash: null,
      };
      if (
        stored === null ||
        checkpointIsStale(stored, this.path, inode, info.size, observedHash)
      ) {
        this.checkpoints.save(this.name, initial);
        this.currentCheckpoint = initial;
      } else {
        this.currentCheckpoint = stored;
      }
      this.activeFile = { inode, size: info.size, fileId };

      yield* this.readSnapshot(handle, info.size, fileId, signal);
    } finally {
      this.activeFile = null;
      this.reading = false;
      await handle?.close();
    }
  }

  private async *readSnapshot(
    handle: FileHandle,
    fileSize: number,
    fileId: string,
    signal: AbortSignal,
  ): AsyncIterable<RawRecord> {
    let position = this.currentCheckpoint.offset;
    let recordStart = position;
    let lineCursor = this.currentCheckpoint.lineNumber;
    let recordStartLine = lineCursor + 1;
    let recordSize = 0;
    let capturedSize = 0;
    let oversized = false;
    let pendingNewline = false;
    let pendingCarriageReturn = false;
    const captured = Buffer.alloc(this.maxRecordBytes);
    const input = Buffer.alloc(this.chunkBytes);

    const append = (byte: number): void => {
      if (capturedSize < this.maxRecordBytes) {
        captured[capturedSize] = byte;
        capturedSize += 1;
      } else {
        oversized = true;
      }
      recordSize += 1;
    };

    const makeRecord = async (
      nextOffset: number,
      nextLineNumber: number,
    ): Promise<RawRecord> => ({
      source: this.name,
      sourceType: this.sourceType,
      offset: recordStart,
      nextOffset,
      lineNumber: recordStartLine,
      nextLineNumber,
      content: captured.subarray(0, capturedSize).toString("utf8"),
      empty: recordSize === 0 && !oversized,
      oversized,
      fileId,
      checkpointHash: (await hashTail(handle, nextOffset)) ?? "",
    });

    const resetRecord = (nextOffset: number, nextLineNumber: number): void => {
      recordStart = nextOffset;
      lineCursor = nextLineNumber;
      recordStartLine = lineCursor + 1;
      recordSize = 0;
      capturedSize = 0;
      oversized = false;
    };

    const emit = async function* (
      nextOffset: number,
      nextLineNumber: number,
    ): AsyncIterable<RawRecord> {
      const record = await makeRecord(nextOffset, nextLineNumber);
      yield record;
      resetRecord(nextOffset, nextLineNumber);
    };

    while (position < fileSize) {
      throwIfAborted(signal);
      const bytesToRead = Math.min(input.length, fileSize - position);
      const { bytesRead } = await handle.read(input, 0, bytesToRead, position);
      if (bytesRead === 0) break;

      for (let index = 0; index < bytesRead; index += 1) {
        const byte = input[index];
        if (byte === undefined) continue;
        const absoluteOffset = position + index;

        if (this.separator === "line") {
          if (byte === 0x0a) {
            if (capturedSize > 0 && captured[capturedSize - 1] === 0x0d) {
              capturedSize -= 1;
              recordSize -= 1;
            }
            yield* emit(absoluteOffset + 1, lineCursor + 1);
          } else {
            append(byte);
          }
          continue;
        }

        if (pendingCarriageReturn) {
          if (byte === 0x0a) {
            pendingCarriageReturn = false;
            lineCursor += 1;
            if (pendingNewline) {
              yield* emit(absoluteOffset + 1, lineCursor);
              pendingNewline = false;
            } else {
              pendingNewline = true;
            }
            continue;
          }
          if (pendingNewline) {
            append(0x0a);
            pendingNewline = false;
          }
          append(0x0d);
          pendingCarriageReturn = false;
        }

        if (byte === 0x0d) {
          pendingCarriageReturn = true;
        } else if (byte === 0x0a) {
          lineCursor += 1;
          if (pendingNewline) {
            yield* emit(absoluteOffset + 1, lineCursor);
            pendingNewline = false;
          } else {
            pendingNewline = true;
          }
        } else {
          if (pendingNewline) {
            append(0x0a);
            pendingNewline = false;
          }
          append(byte);
        }
      }
      position += bytesRead;
    }
  }
}

async function hashTail(
  handle: FileHandle,
  offset: number,
): Promise<string | null> {
  const length = Math.min(offset, CHECKPOINT_HASH_BYTES);
  if (length === 0) return null;
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, offset - length);
  if (bytesRead !== length) return null;
  return createHash("sha256").update(buffer).digest("hex");
}

function throwIfAborted(signal: AbortSignal): void {
  if (!signal.aborted) return;
  const error = new Error("source read was aborted");
  error.name = "AbortError";
  throw error;
}
