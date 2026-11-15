import type { Checkpoint } from "../types.js";

export function checkpointIsStale(
  checkpoint: Checkpoint,
  path: string,
  inode: string,
  size: number,
  observedHash: string | null,
): boolean {
  if (
    checkpoint.path !== path ||
    checkpoint.inode !== inode ||
    size < checkpoint.size ||
    checkpoint.offset > size
  ) {
    return true;
  }
  if (checkpoint.offset === 0) return false;
  return (
    checkpoint.lastHash === null ||
    observedHash === null ||
    checkpoint.lastHash !== observedHash
  );
}
