import type { CheckpointRepository } from "../types.js";
import { FileTailReader } from "./reader-file.js";

export interface NdjsonSourceOptions {
  readonly name: string;
  readonly path: string;
  readonly checkpoints: CheckpointRepository;
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
  readonly chunkBytes?: number;
}

export function createNdjsonSource(
  options: NdjsonSourceOptions,
): FileTailReader {
  return new FileTailReader({ ...options, sourceType: "ndjson" });
}
