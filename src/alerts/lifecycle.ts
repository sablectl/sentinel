import type { Alert, AlertNote } from "../types.js";
import type { AlertStore } from "./store.js";

export class AlertLifecycle {
  constructor(private readonly alerts: AlertStore) {}

  acknowledge(alertId: number): Alert {
    const alert = this.alerts.get(alertId);
    if (alert.state === "acknowledged") return alert;
    if (alert.state === "resolved") {
      throw new Error(
        "a resolved alert must be reopened before acknowledgement",
      );
    }
    return this.alerts.setState(alertId, "acknowledged");
  }

  resolve(alertId: number): Alert {
    const alert = this.alerts.get(alertId);
    if (alert.state === "resolved") return alert;
    return this.alerts.setState(alertId, "resolved");
  }

  reopen(alertId: number): Alert {
    const alert = this.alerts.get(alertId);
    if (alert.state === "open") return alert;
    if (alert.state === "acknowledged") {
      throw new Error(
        "an acknowledged alert must be resolved before reopening",
      );
    }
    return this.alerts.setState(alertId, "open");
  }

  addNote(alertId: number, note: string): AlertNote {
    return this.alerts.addNote(alertId, note);
  }
}
