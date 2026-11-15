import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteCheckpointStore } from "../../src/ingest/checkpoint.js";
import { BoundedQueue } from "../../src/ingest/queue.js";
import { FileTailReader } from "../../src/ingest/reader-file.js";
import { createJournalSource } from "../../src/ingest/source-journal.js";
import { EventDatabase } from "../../src/store/database.js";
import { parseJournal } from "../../src/parse/journal.js";
import { parseNdjson } from "../../src/parse/ndjson.js";

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-ingest-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function reader(
  path: string,
  checkpoints: SqliteCheckpointStore,
  maxRecordBytes = 1024,
): FileTailReader {
  return new FileTailReader({
    name: "test-source",
    sourceType: "ndjson",
    path,
    checkpoints,
    maxRecordBytes,
    maxFileBytes: 1024 * 1024,
    chunkBytes: 7,
  });
}

async function readAndCommit(source: FileTailReader): Promise<string[]> {
  const records: string[] = [];
  for await (const record of source.read(new AbortController().signal)) {
    records.push(record.content);
    source.commit(record);
  }
  return records;
}

describe("FileTailReader", () => {
  it("commits complete records and resumes after an appended partial record", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "events.ndjson");
    await writeFile(path, "first\npartial", "utf8");
    const database = new EventDatabase({ path: ":memory:" });
    const checkpoints = new SqliteCheckpointStore(database);
    try {
      expect(await readAndCommit(reader(path, checkpoints))).toEqual(["first"]);
      expect(await readAndCommit(reader(path, checkpoints))).toEqual([]);
      await writeFile(path, "first\npartial-line\n", "utf8");
      expect(await readAndCommit(reader(path, checkpoints))).toEqual([
        "partial-line",
      ]);
    } finally {
      database.close();
    }
  });

  it("detects an in-place replacement by checking the checkpoint fingerprint", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "events.ndjson");
    await writeFile(path, "one\n", "utf8");
    const database = new EventDatabase({ path: ":memory:" });
    const checkpoints = new SqliteCheckpointStore(database);
    try {
      expect(await readAndCommit(reader(path, checkpoints))).toEqual(["one"]);
      await writeFile(path, "two\n", "utf8");
      expect(await readAndCommit(reader(path, checkpoints))).toEqual(["two"]);
    } finally {
      database.close();
    }
  });

  it("caps oversized record memory, reports the record, and advances after commit", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "events.ndjson");
    await writeFile(path, `${"x".repeat(30)}\nvalid\n`, "utf8");
    const database = new EventDatabase({ path: ":memory:" });
    const checkpoints = new SqliteCheckpointStore(database);
    const source = reader(path, checkpoints, 8);
    try {
      const results = [];
      for await (const record of source.read(new AbortController().signal)) {
        results.push({ content: record.content, oversized: record.oversized });
        source.commit(record);
      }
      expect(results).toEqual([
        { content: "xxxxxxxx", oversized: true },
        { content: "valid", oversized: false },
      ]);
      const parsed = parseNdjson({
        source: "test-source",
        sourceType: "ndjson",
        offset: 0,
        nextOffset: 31,
        lineNumber: 1,
        nextLineNumber: 2,
        content: results[0]?.content ?? "",
        empty: false,
        oversized: true,
        fileId: "1:2",
        checkpointHash: "hash",
      });
      expect(parsed.ok).toBe(false);
    } finally {
      database.close();
    }
  });

  it("rejects a file that exceeds the configured total size", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "events.ndjson");
    await writeFile(path, "123456789", "utf8");
    const database = new EventDatabase({ path: ":memory:" });
    const checkpoints = new SqliteCheckpointStore(database);
    try {
      const source = new FileTailReader({
        name: "limited",
        sourceType: "ndjson",
        path,
        checkpoints,
        maxRecordBytes: 4,
        maxFileBytes: 8,
      });
      await expect(async () => {
        for await (const record of source.read(new AbortController().signal)) {
          source.commit(record);
        }
      }).rejects.toThrow(/above the configured limit/);
    } finally {
      database.close();
    }
  });

  it("reads blank-line-delimited journal export records across CRLF chunk boundaries", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "journal.export");
    const content =
      "__REALTIME_TIMESTAMP=1000000\r\nMESSAGE=first record\r\n_HOSTNAME=host-a\r\n\r\n" +
      "__REALTIME_TIMESTAMP=2000000\r\nMESSAGE=second record\r\n_HOSTNAME=host-b\r\n\r\n";
    await writeFile(path, content, "utf8");
    const database = new EventDatabase({ path: ":memory:" });
    const checkpoints = new SqliteCheckpointStore(database);
    const source = createJournalSource({
      name: "journal-export",
      path,
      checkpoints,
      maxRecordBytes: 1024,
      maxFileBytes: 4096,
      chunkBytes: 5,
    });
    try {
      const records = [];
      for await (const record of source.read(new AbortController().signal)) {
        records.push(record);
        source.commit(record);
      }
      expect(records.map(({ content: record }) => record)).toEqual([
        "__REALTIME_TIMESTAMP=1000000\nMESSAGE=first record\n_HOSTNAME=host-a",
        "__REALTIME_TIMESTAMP=2000000\nMESSAGE=second record\n_HOSTNAME=host-b",
      ]);
      expect(records.map(({ lineNumber }) => lineNumber)).toEqual([1, 5]);
      expect(records.map((record) => parseJournal(record).ok)).toEqual([
        true,
        true,
      ]);
    } finally {
      database.close();
    }
  });
});

describe("BoundedQueue", () => {
  it("applies backpressure once its high-water mark is reached", async () => {
    const queue = new BoundedQueue<number>(1);
    await queue.push(1);
    let secondPushFinished = false;
    const secondPush = queue.push(2).then(() => {
      secondPushFinished = true;
    });
    await Promise.resolve();
    expect(secondPushFinished).toBe(false);

    expect(await queue.next()).toEqual({ value: 1, done: false });
    await secondPush;
    expect(queue.size).toBe(1);
    expect(await queue.next()).toEqual({ value: 2, done: false });
    queue.close();
    expect(await queue.next()).toEqual({ value: undefined, done: true });
  });

  it("unblocks a waiting producer when its signal is aborted", async () => {
    const queue = new BoundedQueue<number>(1);
    await queue.push(1);
    const controller = new AbortController();
    const blocked = queue.push(2, controller.signal);
    controller.abort();
    await expect(blocked).rejects.toMatchObject({ name: "AbortError" });
    queue.close();
  });
});
