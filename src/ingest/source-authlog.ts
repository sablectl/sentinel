import type { CheckpointRepository } from "../types.js";
import { FileTailReader } from "./reader-file.js";

export interface FileSourceOptions {
  readonly name: string;
  readonly path: string;
  readonly checkpoints: CheckpointRepository;
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
  readonly chunkBytes?: number;
}

export function createAuthlogSource(
  options: FileSourceOptions,
): FileTailReader {
  return new FileTailReader({ ...options, sourceType: "authlog" });
}
