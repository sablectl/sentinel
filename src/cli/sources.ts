import type { Config } from "../config/config.js";
import { EventDatabase } from "../store/database.js";
import { getSourceStatuses, type SourceStatus } from "../store/queries.js";

export function listSources(config: Config): SourceStatus[] {
  const database = new EventDatabase({ path: config.storage.path });
  try {
    return database.withDatabase(getSourceStatuses);
  } finally {
    database.close();
  }
}
