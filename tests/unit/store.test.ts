import { chmod, mkdir, mkdtemp, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EventDatabase } from "../../src/store/database.js";
import { MIGRATIONS, SCHEMA_VERSION } from "../../src/store/migrations.js";

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "sentinel-store-"));
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

describe("EventDatabase", () => {
  it("applies ordered migrations and records the schema version", () => {
    const database = new EventDatabase({ path: ":memory:" });
    try {
      expect(database.schemaVersion).toBe(SCHEMA_VERSION);
      expect(database.integrityCheck()).toBe("ok");
      const versions = database.withDatabase((connection) =>
        connection
          .prepare("SELECT version FROM schema_migrations ORDER BY version")
          .all()
          .map((row) => row["version"]),
      );
      expect(versions).toEqual(MIGRATIONS.map(({ version }) => version));
      expect(database.counts()).toEqual({
        events: 0,
        parseFailures: 0,
        sources: 0,
        alerts: 0,
      });
    } finally {
      database.close();
    }
  });

  it("is idempotent when an existing database is reopened", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "events.sqlite");
    const first = new EventDatabase({ path });
    first.close();

    const second = new EventDatabase({ path });
    try {
      expect(second.integrityCheck()).toBe("ok");
      const versions = second.withDatabase((connection) =>
        connection
          .prepare("SELECT version FROM schema_migrations ORDER BY version")
          .all()
          .map((row) => row["version"]),
      );
      expect(versions).toEqual(MIGRATIONS.map(({ version }) => version));
    } finally {
      second.close();
    }
  });

  it("creates the database directory and file with owner-only permissions", async () => {
    const directory = await temporaryDirectory();
    const stateDirectory = join(directory, "state");
    const path = join(stateDirectory, "events.sqlite");
    const database = new EventDatabase({ path });
    database.close();

    expect((await stat(stateDirectory)).mode & 0o777).toBe(0o700);
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it("does not change permissions on an existing shared parent directory", async () => {
    const directory = await temporaryDirectory();
    const sharedDirectory = join(directory, "shared");
    await mkdir(sharedDirectory, { mode: 0o755 });
    await chmod(sharedDirectory, 0o755);
    const database = new EventDatabase({
      path: join(sharedDirectory, "events.sqlite"),
    });
    database.close();

    expect((await stat(sharedDirectory)).mode & 0o777).toBe(0o755);
  });

  it("rejects symlinked and unsafe shared database parent directories", async () => {
    const directory = await temporaryDirectory();
    const realDirectory = join(directory, "real");
    const linkedDirectory = join(directory, "linked");
    const unsafeDirectory = join(directory, "unsafe");
    await mkdir(realDirectory, { mode: 0o700 });
    await symlink(realDirectory, linkedDirectory);
    await mkdir(unsafeDirectory, { mode: 0o777 });
    await chmod(unsafeDirectory, 0o777);

    expect(
      () => new EventDatabase({ path: join(linkedDirectory, "events.sqlite") }),
    ).toThrow(/directory, not a symlink/);
    expect(
      () => new EventDatabase({ path: join(unsafeDirectory, "events.sqlite") }),
    ).toThrow(/writable by other users/);
  });

  it("rejects a symlink as the database path", async () => {
    const directory = await temporaryDirectory();
    const target = join(directory, "target.sqlite");
    const link = join(directory, "events.sqlite");
    const seed = new EventDatabase({ path: target });
    seed.close();
    await symlink(target, link);

    expect(() => new EventDatabase({ path: link })).toThrow(/regular file/);
  });
});
