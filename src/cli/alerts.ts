import type { Config } from "../config/config.js";
import { AlertLifecycle } from "../alerts/lifecycle.js";
import { AlertStore } from "../alerts/store.js";
import { EventDatabase } from "../store/database.js";
import type { Invocation } from "./args.js";
import { UsageError } from "./args.js";

export function runAlerts(config: Config, invocation: Invocation): string {
  const database = new EventDatabase({ path: config.storage.path });
  try {
    const store = new AlertStore(database);
    const lifecycle = new AlertLifecycle(store);
    const action = invocation.action ?? "list";
    if (action === "list") {
      return `${JSON.stringify(
        store.list({
          ...(invocation.alertState === undefined
            ? {}
            : { state: invocation.alertState }),
          ...(invocation.alertSeverity === undefined
            ? {}
            : { severity: invocation.alertSeverity }),
          ...(invocation.limit === undefined
            ? {}
            : { limit: invocation.limit }),
        }),
        null,
        2,
      )}\n`;
    }

    const alertId = parseAlertId(invocation.identifier);
    if (action === "acknowledge") {
      return `${JSON.stringify(lifecycle.acknowledge(alertId), null, 2)}\n`;
    }
    if (action === "resolve") {
      return `${JSON.stringify(lifecycle.resolve(alertId), null, 2)}\n`;
    }
    if (action === "reopen") {
      return `${JSON.stringify(lifecycle.reopen(alertId), null, 2)}\n`;
    }
    if (action === "note") {
      if (invocation.note === undefined) {
        throw new UsageError("alerts note requires --note text");
      }
      return `${JSON.stringify(lifecycle.addNote(alertId, invocation.note), null, 2)}\n`;
    }
    throw new UsageError(`unknown alerts action: ${action}`);
  } finally {
    database.close();
  }
}

function parseAlertId(value: string | undefined): number {
  if (value === undefined || !/^\d+$/.test(value)) {
    throw new UsageError(
      "alert action requires a positive integer alert identifier",
    );
  }
  const alertId = Number(value);
  if (!Number.isSafeInteger(alertId) || alertId < 1) {
    throw new UsageError(
      "alert action requires a positive integer alert identifier",
    );
  }
  return alertId;
}
