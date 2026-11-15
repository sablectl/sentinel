import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";

export function writeExportFile(outputPath: string, contents: string): string {
  const target = resolve(outputPath);
  const directory = dirname(target);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  try {
    const info = lstatSync(target);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error(
        "export destination must be a regular file, not a symlink",
      );
    }
  } catch (error: unknown) {
    if (!isMissingFile(error)) throw error;
  }

  const temporary = resolve(
    directory,
    `.${basename(target)}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        fsConstants.O_NOFOLLOW,
      0o600,
    );
    writeFileSync(descriptor, contents, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, target);
    return target;
  } catch (error: unknown) {
    if (descriptor !== undefined) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch {
      // The temporary path may not have been created.
    }
    throw error;
  }
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    error.code === "ENOENT"
  );
}
