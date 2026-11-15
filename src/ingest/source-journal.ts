import type { CheckpointRepository } from "../types.js";
import { FileTailReader } from "./reader-file.js";

export interface JournalSourceOptions {
  readonly name: string;
  readonly path: string;
  readonly checkpoints: CheckpointRepository;
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
  readonly chunkBytes?: number;
}

export function createJournalSource(
  options: JournalSourceOptions,
): FileTailReader {
  return new FileTailReader({
    ...options,
    sourceType: "journal",
    separator: "blank-line",
  });
}
