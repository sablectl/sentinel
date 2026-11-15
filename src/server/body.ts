import type { IncomingMessage } from "node:http";

export class HttpInputError extends Error {
  constructor(
    readonly status: 400 | 413 | 415,
    message: string,
  ) {
    super(message);
    this.name = "HttpInputError";
  }
}

export async function readJsonBody(
  request: IncomingMessage,
  maximumBytes: number,
): Promise<Record<string, unknown>> {
  const contentType = request.headers["content-type"];
  if (
    typeof contentType !== "string" ||
    contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json"
  ) {
    request.resume();
    throw new HttpInputError(415, "content type must be application/json");
  }
  const contentLength = request.headers["content-length"];
  if (contentLength !== undefined) {
    if (!/^\d+$/.test(contentLength)) {
      request.resume();
      throw new HttpInputError(400, "content length is invalid");
    }
    if (Number(contentLength) > maximumBytes) {
      request.resume();
      throw new HttpInputError(
        413,
        "request body exceeds the configured limit",
      );
    }
  }

  const chunks: Buffer[] = [];
  let size = 0;
  let tooLarge = false;
  await new Promise<void>((resolve, reject) => {
    const cleanup = (): void => {
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("aborted", onAborted);
      request.off("error", onError);
    };
    const onData = (chunk: Buffer | string): void => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.byteLength;
      if (size > maximumBytes) {
        tooLarge = true;
        chunks.length = 0;
        request.resume();
        return;
      }
      if (!tooLarge) chunks.push(buffer);
    };
    const onEnd = (): void => {
      cleanup();
      if (tooLarge)
        reject(
          new HttpInputError(413, "request body exceeds the configured limit"),
        );
      else resolve();
    };
    const onAborted = (): void => {
      cleanup();
      reject(new HttpInputError(400, "request body was interrupted"));
    };
    const onError = (): void => {
      cleanup();
      reject(new HttpInputError(400, "request body could not be read"));
    };
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("aborted", onAborted);
    request.once("error", onError);
  });

  if (size === 0) throw new HttpInputError(400, "request body is empty");
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      Buffer.concat(chunks, size).toString("utf8"),
    ) as unknown;
  } catch {
    throw new HttpInputError(400, "request body is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new HttpInputError(400, "request body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}
