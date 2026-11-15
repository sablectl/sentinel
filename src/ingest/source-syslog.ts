import type { CheckpointRepository } from "../types.js";
import { FileTailReader } from "./reader-file.js";

export interface SyslogSourceOptions {
  readonly name: string;
  readonly path: string;
  readonly checkpoints: CheckpointRepository;
  readonly maxRecordBytes: number;
  readonly maxFileBytes: number;
  readonly chunkBytes?: number;
}

export function createSyslogSource(
  options: SyslogSourceOptions,
): FileTailReader {
  return new FileTailReader({ ...options, sourceType: "syslog" });
}
