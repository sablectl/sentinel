export type ConnectionState =
  "connecting" | "live" | "reconnecting" | "offline";

export interface StreamEvent {
  readonly type: string;
  readonly payload: unknown;
}

export interface AppState {
  readonly authenticated: boolean;
  readonly connection: ConnectionState;
  readonly degraded: number;
  readonly currentView: string;
}

export class Emitter<T> {
  private readonly listeners = new Set<(value: T) => void>();

  on(listener: (value: T) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(value: T): void {
    for (const listener of this.listeners) listener(value);
  }
}

export const state: AppState = {
  authenticated: false,
  connection: "connecting",
  degraded: 0,
  currentView: "overview",
};

export const stateEvents = new Emitter<AppState>();
export const streamEvents = new Emitter<StreamEvent>();

export function updateState(update: Partial<AppState>): void {
  Object.assign(state, update);
  stateEvents.emit(state);
}
