import type { Config } from "../config/config.js";
import { EventDatabase } from "../store/database.js";
import { getSourceStatuses } from "../store/queries.js";
import { getRetentionDays } from "../store/system-settings.js";
import { VERSION } from "../version.js";

export function runStatus(config: Config): string {
  const database = new EventDatabase({ path: config.storage.path });
  try {
    const result = {
      version: VERSION,
      schemaVersion: database.schemaVersion,
      integrity: database.integrityCheck(),
      counts: database.counts(),
      sources: database.withDatabase(getSourceStatuses),
      retentionDays: database.withDatabase((connection) =>
        getRetentionDays(connection, config.storage.retentionDays),
      ),
    };
    return `${JSON.stringify(result, null, 2)}\n`;
  } finally {
    database.close();
  }
}
