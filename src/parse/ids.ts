import { createHash } from "node:crypto";
import type { RawRecord, SecurityEvent } from "../types.js";

type EventIdentity = Omit<SecurityEvent, "id" | "ingestedAt">;

export function createEventId(
  record: Pick<RawRecord, "source" | "offset">,
  event: EventIdentity,
): string {
  const hash = createHash("sha256");
  hash.update(record.source, "utf8");
  hash.update("\0", "utf8");
  hash.update(String(record.offset), "utf8");
  hash.update("\0", "utf8");
  hash.update(stableEventContent(event), "utf8");
  return hash.digest("hex");
}

function stableEventContent(event: EventIdentity): string {
  const metadata = Object.fromEntries(
    Object.entries(event.metadata).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  );
  return JSON.stringify({ ...event, metadata });
}
