import type { ServerResponse } from "node:http";

const MAX_FRAME_BYTES = 2_097_152;

interface StreamClient {
  readonly response: ServerResponse;
  saturated: boolean;
  dropped: number;
  rateWindowStart: number;
  sentInWindow: number;
  heartbeat: NodeJS.Timeout;
}

export class EventStream {
  private readonly clients = new Set<StreamClient>();

  constructor(
    private readonly maximumClients: number,
    private readonly maximumEventsPerSecond = 100,
    private readonly heartbeatMs = 20_000,
  ) {
    if (
      !Number.isSafeInteger(maximumClients) ||
      maximumClients < 1 ||
      !Number.isSafeInteger(maximumEventsPerSecond) ||
      maximumEventsPerSecond < 1 ||
      maximumEventsPerSecond > 10_000 ||
      !Number.isSafeInteger(heartbeatMs) ||
      heartbeatMs < 1_000
    ) {
      throw new RangeError("event stream limits are invalid");
    }
  }

  get clientCount(): number {
    return this.clients.size;
  }

  subscribe(response: ServerResponse): (() => void) | null {
    if (this.clients.size >= this.maximumClients) return null;
    const client: StreamClient = {
      response,
      saturated: false,
      dropped: 0,
      rateWindowStart: Date.now(),
      sentInWindow: 0,
      heartbeat: setInterval(() => {
        if (
          !client.saturated &&
          !response.destroyed &&
          !response.writableEnded
        ) {
          this.write(client, ": keep-alive\n\n");
        }
      }, this.heartbeatMs),
    };
    client.heartbeat.unref();
    this.clients.add(client);
    const remove = (): void => {
      clearInterval(client.heartbeat);
      this.clients.delete(client);
    };
    response.once("close", remove);
    response.once("error", remove);
    return remove;
  }

  publish(event: string, payload: unknown): void {
    if (!/^[a-z][a-z0-9._-]{0,63}$/.test(event)) return;
    const json = JSON.stringify(payload);
    if (json === undefined) return;
    const frame = `event: ${event}\ndata: ${json}\n\n`;
    if (Buffer.byteLength(frame, "utf8") > MAX_FRAME_BYTES) {
      for (const client of this.clients) {
        client.dropped += 1;
      }
      return;
    }
    for (const client of this.clients) {
      if (
        client.saturated ||
        client.response.destroyed ||
        client.response.writableEnded
      ) {
        client.dropped += 1;
        continue;
      }
      if (client.dropped > 0) {
        const dropped = client.dropped;
        client.dropped = 0;
        this.publishToClient(client, "stream.degraded", { dropped });
      }
      if (client.saturated) {
        client.dropped += 1;
        continue;
      }
      if (!this.takeRateSlot(client, Date.now())) {
        client.dropped += 1;
        continue;
      }
      this.write(client, frame);
    }
  }

  close(): void {
    for (const client of this.clients) {
      clearInterval(client.heartbeat);
      if (!client.response.writableEnded) client.response.end();
    }
    this.clients.clear();
  }

  private write(client: StreamClient, frame: string): void {
    if (client.response.destroyed || client.response.writableEnded) return;
    if (client.response.write(frame)) return;
    client.saturated = true;
    client.response.once("drain", () => {
      if (!this.clients.has(client)) return;
      client.saturated = false;
      if (client.dropped === 0) return;
      const dropped = client.dropped;
      client.dropped = 0;
      this.publishToClient(client, "stream.degraded", { dropped });
    });
  }

  private publishToClient(
    client: StreamClient,
    event: string,
    payload: unknown,
  ): void {
    if (!/^[a-z][a-z0-9._-]{0,63}$/.test(event)) return;
    const json = JSON.stringify(payload);
    if (json === undefined) return;
    const frame = `event: ${event}\ndata: ${json}\n\n`;
    if (Buffer.byteLength(frame, "utf8") > MAX_FRAME_BYTES) return;
    this.write(client, frame);
  }

  private takeRateSlot(client: StreamClient, now: number): boolean {
    if (now - client.rateWindowStart >= 1_000) {
      client.rateWindowStart = now;
      client.sentInWindow = 0;
    }
    if (client.sentInWindow >= this.maximumEventsPerSecond) return false;
    client.sentInWindow += 1;
    return true;
  }
}
