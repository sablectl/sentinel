import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = join(projectRoot, "src", "web");
const outputRoot = join(projectRoot, "dist", "web");

await mkdir(outputRoot, { recursive: true });
await Promise.all(
  ["index.html", "styles.css"].map((file) =>
    copyFile(join(sourceRoot, file), join(outputRoot, file)),
  ),
);
