import type { Config } from "../config/config.js";
import { EventDatabase } from "../store/database.js";
import { queryEvents } from "../store/event-queries.js";
import { exportCsv } from "../export/csv.js";
import { exportJson } from "../export/json.js";
import { prepareExport } from "../export/metadata.js";
import { getRelevantRuleReferences } from "../export/references.js";
import { writeExportFile } from "../export/write-file.js";
import { parseEventQuery } from "../server/query.js";
import { UsageError } from "./args.js";

export type ExportFormat = "json" | "csv";

export interface ExportOptions {
  readonly format: ExportFormat | undefined;
  readonly outputPath: string | undefined;
  readonly filters: Readonly<Record<string, string>>;
}

export function runExport(
  config: Config,
  options: ExportOptions,
): {
  readonly path: string;
  readonly eventCount: number;
  readonly filteredTotal: number;
} {
  if (options.format === undefined) {
    throw new UsageError("export requires --format json or csv");
  }
  const parsed = parseEventQuery(
    new URLSearchParams(options.filters),
    Date.now(),
  );
  if (!parsed.ok)
    throw new UsageError(`invalid export filters: ${parsed.error}`);

  const database = new EventDatabase({ path: config.storage.path });
  try {
    const page = database.withDatabase((connection) =>
      queryEvents(connection, parsed.value),
    );
    const relevantRules = database.withDatabase((connection) =>
      getRelevantRuleReferences(
        connection,
        page.events.map((event) => event.id),
      ),
    );
    const prepared = prepareExport(
      page.events,
      parsed.value,
      relevantRules,
      config.export.redactSensitiveFields,
    );
    const contents =
      options.format === "json" ? exportJson(prepared) : exportCsv(prepared);
    const filename = `sentinel-export-${new Date().toISOString().replace(/[:.]/g, "-")}.${options.format}`;
    const path = writeExportFile(options.outputPath ?? filename, contents);
    return {
      path,
      eventCount: page.events.length,
      filteredTotal: page.total,
    };
  } finally {
    database.close();
  }
}
