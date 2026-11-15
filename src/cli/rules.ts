import type { Config } from "../config/config.js";
import { DetectionEngine } from "../detect/engine.js";
import type { Invocation } from "./args.js";
import { UsageError } from "./args.js";
import { EventDatabase } from "../store/database.js";

export function runRules(config: Config, invocation: Invocation): string {
  const database = new EventDatabase({ path: config.storage.path });
  try {
    const engine = new DetectionEngine(database, config.detection);
    const action = invocation.action ?? "list";
    if (action === "list") {
      return `${JSON.stringify(engine.listRules(), null, 2)}\n`;
    }

    const ruleId = requiredIdentifier(invocation.identifier, "rule");
    if (action === "enable" || action === "disable") {
      const rule = engine.configureRule(ruleId, {
        enabled: action === "enable",
      });
      return `${JSON.stringify(rule, null, 2)}\n`;
    }
    if (action === "tune") {
      if (invocation.thresholds === undefined) {
        throw new UsageError(
          "rules tune requires --thresholds with a JSON object",
        );
      }
      const rule = engine.configureRule(ruleId, {
        thresholds: invocation.thresholds,
      });
      return `${JSON.stringify(rule, null, 2)}\n`;
    }
    throw new UsageError(`unknown rules action: ${action}`);
  } finally {
    database.close();
  }
}

function requiredIdentifier(value: string | undefined, label: string): string {
  if (value === undefined || value.length === 0) {
    throw new UsageError(`rules action requires a ${label} identifier`);
  }
  return value;
}
