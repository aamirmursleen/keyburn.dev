import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CliError } from "../../src/cli/errors";
import {
  DEFAULT_TTL_MS,
  attachmentDir,
  ensureVault,
  forgetAll,
  forgetItem,
  listItems,
  loadItem,
  osssHome,
  storeItem,
  sweepAttachments,
  sweepExpired,
  type LocalItem,
} from "../../src/cli/vault";

const item: LocalItem = {
  v: 1,
  text: "API_KEY=s3cr3t-value",
  file: { name: "a.txt", type: "text/plain", data: "aGk" },
  origin: "https://secret.nafran.com",
  openedAt: 1_700_000_000_000,
};

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CliError) return error.code;
    throw error;
  }
  return "no error";
}

let root: string;
let home: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "osss-test-"));
  home = join(root, "home");
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

describe("osssHome", () => {
  it("uses OSSS_HOME when set, otherwise ~/.osss", () => {
    expect(osssHome({ OSSS_HOME: "/x/y" })).toBe("/x/y");
    expect(osssHome({})).toMatch(/\.osss$/);
  });
});

describe("storeItem / loadItem", () => {
  it("round-trips and never writes plaintext", async () => {
    const stored = await storeItem(home, item);
    expect(stored.handle).toMatch(/^osss_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43}$/);
    expect(stored.handle.slice(5, 21)).toBe(stored.id);
    expect(stored.expiresAt).toBeGreaterThan(Date.now() + DEFAULT_TTL_MS - 60_000);

    const files = await readdir(join(home, "vault"));
    expect(files).toEqual([`${stored.id}.${stored.expiresAt}.bin`]);
    const raw = await readFile(join(home, "vault", files[0]!));
    expect(raw.includes(Buffer.from("s3cr3t"))).toBe(false);
    expect(raw.includes(Buffer.from("API_KEY"))).toBe(false);

    expect(await loadItem(home, stored.handle)).toEqual(item);
    expect(await loadItem(home, `  ${stored.handle}\n`)).toEqual(item);
  });

  it("creates private directories and files", async () => {
    if (process.platform === "win32") return;
    const stored = await storeItem(home, item);
    expect((await lstat(home)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(home, "vault"))).mode & 0o777).toBe(0o700);
    expect((await lstat(join(home, "vault", `${stored.id}.${stored.expiresAt}.bin`))).mode & 0o777).toBe(0o600);
  });

  it("tightens loose directory permissions", async () => {
    if (process.platform === "win32") return;
    await mkdir(join(home, "vault"), { recursive: true });
    await chmod(home, 0o755);
    await chmod(join(home, "vault"), 0o777);
    await storeItem(home, item);
    expect((await lstat(home)).mode & 0o777).toBe(0o700);
    expect((await lstat(join(home, "vault"))).mode & 0o777).toBe(0o700);
  });

  it("refuses a vault that is a symbolic link", async () => {
    if (process.platform === "win32") return;
    await mkdir(home, { recursive: true });
    await mkdir(join(root, "elsewhere"));
    await symlink(join(root, "elsewhere"), join(home, "vault"));
    expect(await code(storeItem(home, item))).toBe("unsafe_storage");
  });

  it("checks lifetimes", async () => {
    expect(await code(storeItem(home, item, 59_000))).toBe("usage");
    expect(await code(storeItem(home, item, 8 * 24 * 3_600_000))).toBe("usage");
    expect(await code(storeItem(home, item, 1.5))).toBe("usage");
  });

  it("rejects wrong, malformed and unknown handles", async () => {
    const stored = await storeItem(home, item);
    const other = await storeItem(home, item);
    const wrongKey = `osss_${stored.id}_${other.handle.slice(22)}`;
    expect(await code(loadItem(home, wrongKey))).toBe("bad_handle");
    expect(await code(loadItem(home, "osss_nope"))).toBe("bad_handle");
    expect(await code(loadItem(home, ""))).toBe("bad_handle");
    expect(await code(loadItem(home, `osss_AAAAAAAAAAAAAAAA_${stored.handle.slice(22)}`))).toBe("expired_handle");
  });

  it("detects tampering and renamed files", async () => {
    const stored = await storeItem(home, item);
    const path = join(home, "vault", `${stored.id}.${stored.expiresAt}.bin`);
    const blob = await readFile(path);
    blob[blob.length - 1]! ^= 1;
    await writeFile(path, blob);
    expect(await code(loadItem(home, stored.handle))).toBe("bad_handle");

    // Renaming a file to extend its life breaks the authenticated expiry.
    const fresh = await storeItem(home, item);
    await rename(
      join(home, "vault", `${fresh.id}.${fresh.expiresAt}.bin`),
      join(home, "vault", `${fresh.id}.${fresh.expiresAt + 86_400_000}.bin`),
    );
    expect(await code(loadItem(home, fresh.handle))).toBe("bad_handle");
  });

  it("refuses expired items and deletes them", async () => {
    const stored = await storeItem(home, item, 60_000);
    expect(await code(loadItem(home, stored.handle, stored.expiresAt))).toBe("expired_handle");
    expect(await listItems(home)).toEqual([]);
  });
});

describe("listing and forgetting", () => {
  it("lists ids and expiry only, soonest first", async () => {
    const later = await storeItem(home, item, 2 * 3_600_000);
    const sooner = await storeItem(home, item, 3_600_000);
    expect(await listItems(home)).toEqual([
      { id: sooner.id, expiresAt: sooner.expiresAt },
      { id: later.id, expiresAt: later.expiresAt },
    ]);
  });

  it("sweeps expired items", async () => {
    const short = await storeItem(home, item, 60_000);
    const long = await storeItem(home, item, 3_600_000);
    await sweepExpired(home, short.expiresAt);
    expect((await listItems(home)).map((i) => i.id)).toEqual([long.id]);
  });

  it("forgets by handle or id, and all at once", async () => {
    const a = await storeItem(home, item);
    const b = await storeItem(home, item);
    const c = await storeItem(home, item);
    expect(await forgetItem(home, a.handle)).toBe(true);
    expect(await forgetItem(home, b.id)).toBe(true);
    expect(await forgetItem(home, b.id)).toBe(false);
    expect(await code(forgetItem(home, "not a handle"))).toBe("bad_handle");
    expect(await code(loadItem(home, a.handle))).toBe("expired_handle");
    expect(await forgetAll(home)).toBe(1);
    expect(await code(loadItem(home, c.handle))).toBe("expired_handle");
    expect(await forgetAll(home)).toBe(0);
  });

  it("ignores unrelated files", async () => {
    await mkdir(join(home, "vault"), { recursive: true });
    await writeFile(join(home, "vault", "notes.txt"), "x");
    expect(await listItems(home)).toEqual([]);
    expect(await forgetAll(home)).toBe(0);
    expect(await readdir(join(home, "vault"))).toEqual(["notes.txt"]);
  });
});

describe("attachments and safety checks", () => {
  it("makes private per-run directories and sweeps ones left by dead runs", async () => {
    const mine = await attachmentDir(home);
    expect(mine.startsWith(join(home, "tmp", `${process.pid}-`))).toBe(true);
    if (process.platform !== "win32") {
      expect((await lstat(mine)).mode & 0o777).toBe(0o700);
      expect((await lstat(join(home, "tmp"))).mode & 0o777).toBe(0o700);
    }
    // A run that was killed: a pid that can't be alive (beyond the pid range).
    await mkdir(join(home, "tmp", "4294967-abc123"));
    await writeFile(join(home, "tmp", "4294967-abc123", "attachment"), "plaintext");
    // Anything else is left alone.
    await mkdir(join(home, "tmp", "not-a-pid"));
    await writeFile(join(home, "tmp", "4294967-file00"), "x");
    await sweepAttachments(home);
    expect((await readdir(join(home, "tmp"))).sort()).toEqual(["4294967-file00", mine.split("/").pop(), "not-a-pid"].sort());
  });

  it("never sweeps through a linked tmp directory or linked entries", async () => {
    if (process.platform === "win32") return;
    const victim = join(root, "victim");
    await mkdir(join(victim, "4294967-abc123"), { recursive: true });
    await writeFile(join(victim, "4294967-abc123", "keep"), "important");
    await mkdir(home, { recursive: true });
    await symlink(victim, join(home, "tmp"));
    await sweepAttachments(home);
    expect(await readdir(join(victim, "4294967-abc123"))).toEqual(["keep"]);

    await rm(join(home, "tmp"));
    await mkdir(join(home, "tmp"));
    await symlink(join(victim, "4294967-abc123"), join(home, "tmp", "4294967-zzz999"));
    await sweepAttachments(home);
    expect(await readdir(join(victim, "4294967-abc123"))).toEqual(["keep"]);
  });

  it("sweeping without a tmp directory does nothing", async () => {
    await sweepAttachments(join(root, "nowhere"));
  });

  it("checks storage up front", async () => {
    await ensureVault(home);
    expect((await lstat(join(home, "vault"))).isDirectory()).toBe(true);
  });

  it("ignores symbolic links planted in the vault", async () => {
    if (process.platform === "win32") return;
    const stored = await storeItem(home, item);
    const path = join(home, "vault", `${stored.id}.${stored.expiresAt}.bin`);
    const real = join(root, "real.bin");
    await rename(path, real);
    await symlink(real, path);
    expect(await code(loadItem(home, stored.handle))).toBe("expired_handle");
    expect(await listItems(home)).toEqual([]);
    expect(await forgetAll(home)).toBe(0);
  });
});
