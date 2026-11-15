import type { Config } from "../config/config.js";
import { EventDatabase } from "../store/database.js";

export interface DoctorResult {
  readonly integrity: string;
  readonly schemaVersion: number;
  readonly counts: ReturnType<EventDatabase["counts"]>;
}

export function runDoctor(config: Config): DoctorResult {
  const database = new EventDatabase({ path: config.storage.path });
  try {
    const integrity = database.integrityCheck();
    if (integrity !== "ok") {
      throw new Error(`database integrity check failed: ${integrity}`);
    }
    return {
      integrity,
      schemaVersion: database.schemaVersion,
      counts: database.counts(),
    };
  } finally {
    database.close();
  }
}
