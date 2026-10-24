// Local storage for opened secrets. Plaintext never touches disk: each item is encrypted with
// its own random key, and that key exists only inside the item's handle
// ("osss_<id>_<key>"). The stored file is useless without the handle, and the handle (which an
// agent sees) is useless without the file on this machine.

import { lstat, mkdir, mkdtemp, open, readdir, chmod, rm, unlink } from "node:fs/promises";
import { constants } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "../shared/crypto";
import { b64urlDecode, b64urlEncode, isB64url, utf8Decode, utf8Encode, type Bytes } from "../shared/encoding";
import { CliError } from "./errors";

const HANDLE = /^osss_([A-Za-z0-9_-]{16})_([A-Za-z0-9_-]{43})$/;
const ITEM_FILE = /^([A-Za-z0-9_-]{16})\.(\d{1,16})\.bin$/;
const ID = /^[A-Za-z0-9_-]{16}$/;
const subtle = crypto.subtle;

export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
export const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface LocalItem {
  v: 1;
  text: string;
  file: { name: string; type: string; data: string } | null;
  origin: string;
  openedAt: number;
}

export interface StoredItem {
  handle: string;
  id: string;
  expiresAt: number;
}

export function osssHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.OSSS_HOME && env.OSSS_HOME.length > 0 ? env.OSSS_HOME : join(homedir(), ".osss");
}

/**
 * Creates (or checks) a private directory: a real directory owned by this user, mode 0700.
 * On Windows the POSIX mode isn't enforced; the user's profile folder permissions apply.
 */
async function privateDir(path: string): Promise<string> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new CliError("unsafe_storage", `${path} is not a private directory.`);
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new CliError("unsafe_storage", `${path} belongs to another user.`);
  }
  if ((info.mode & 0o077) !== 0) await chmod(path, 0o700);
  return path;
}

async function vaultDir(home: string): Promise<string> {
  await privateDir(home);
  return privateDir(join(home, "vault"));
}

/** Checks that opened secrets can be stored, before a link's view is used up. */
export async function ensureVault(home: string): Promise<void> {
  await vaultDir(home);
}

/** Regular files in a directory (never symbolic links or anything else). */
async function files(dir: string): Promise<string[]> {
  return (await readdir(dir, { withFileTypes: true })).filter((entry) => entry.isFile()).map((entry) => entry.name);
}

/**
 * A new private directory for an attachment while a command runs:
 * <home>/tmp/<pid>-<random>, removed by the caller when the command ends.
 */
export async function attachmentDir(home: string): Promise<string> {
  await privateDir(home);
  const root = await privateDir(join(home, "tmp"));
  return mkdtemp(join(root, `${process.pid}-`));
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Whether `path` is a real directory (not a link) owned by this user; never creates it. */
async function isOwnDirectory(path: string): Promise<boolean> {
  try {
    const info = await lstat(path);
    return info.isDirectory() && !info.isSymbolicLink() && (typeof process.getuid !== "function" || info.uid === process.getuid());
  } catch {
    return false;
  }
}

/** mkdtemp names: "<pid>-" plus six random characters. */
const ATTACHMENT_DIR = /^(\d{1,10})-[A-Za-z0-9]{6}$/;

/**
 * Removes attachment directories left behind by runs that ended abnormally (killed, crashed).
 * Only real directories with the exact name format, inside a verified private tmp directory.
 */
export async function sweepAttachments(home: string): Promise<void> {
  const root = join(home, "tmp");
  if (!(await isOwnDirectory(home)) || !(await isOwnDirectory(root))) return;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const m = ATTACHMENT_DIR.exec(entry.name);
    if (!m || !entry.isDirectory() || entry.isSymbolicLink()) continue;
    const pid = Number(m[1]);
    if (pid !== process.pid && !processAlive(pid)) await rm(join(root, entry.name), { recursive: true, force: true }).catch(() => undefined);
  }
}

function additionalData(id: string, expiresAt: number): Bytes {
  // Binds the ciphertext to its id and expiry, so renaming a file can't extend its life.
  return utf8Encode(`osss-local/v1/${id}/${expiresAt}`);
}

async function itemKey(raw: Bytes, usage: KeyUsage): Promise<CryptoKey> {
  return subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
}

/** Deletes items whose time is up. Called on every start. */
export async function sweepExpired(home: string, now = Date.now()): Promise<void> {
  const dir = await vaultDir(home);
  for (const name of await files(dir)) {
    const m = ITEM_FILE.exec(name);
    if (m && Number(m[2]) <= now) await unlink(join(dir, name)).catch(() => undefined);
  }
}

export async function storeItem(home: string, item: LocalItem, ttlMs = DEFAULT_TTL_MS): Promise<StoredItem> {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 60_000 || ttlMs > MAX_TTL_MS) {
    throw new CliError("usage", "The local lifetime must be between 1 minute and 7 days.");
  }
  const dir = await vaultDir(home);
  const id = b64urlEncode(randomBytes(12));
  const keyBytes = randomBytes(32);
  const expiresAt = Date.now() + ttlMs;
  const iv = randomBytes(12);
  const key = await itemKey(keyBytes, "encrypt");
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: additionalData(id, expiresAt) }, key, utf8Encode(JSON.stringify(item))),
  );
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv);
  blob.set(ct, iv.length);
  // Exclusive create: never overwrites and never follows an existing link at that name.
  const handle = await open(join(dir, `${id}.${expiresAt}.bin`), "wx", 0o600);
  try {
    await handle.writeFile(blob);
  } finally {
    await handle.close();
  }
  const handleText = `osss_${id}_${b64urlEncode(keyBytes)}`;
  keyBytes.fill(0);
  return { handle: handleText, id, expiresAt };
}

function parseHandle(handle: string): { id: string; key: Bytes } {
  const m = HANDLE.exec(handle.trim());
  if (!m || !isB64url(m[2], 32)) throw new CliError("bad_handle", "That isn't a valid osss handle.");
  return { id: m[1] as string, key: b64urlDecode(m[2] as string) };
}

async function findItem(dir: string, id: string): Promise<{ path: string; expiresAt: number } | null> {
  for (const name of await files(dir)) {
    const m = ITEM_FILE.exec(name);
    if (m && m[1] === id) return { path: join(dir, name), expiresAt: Number(m[2]) };
  }
  return null;
}

function checkItem(v: unknown): LocalItem {
  const o = v as Partial<LocalItem> | null;
  const f = o?.file;
  if (
    !o ||
    o.v !== 1 ||
    typeof o.text !== "string" ||
    typeof o.origin !== "string" ||
    !Number.isSafeInteger(o.openedAt) ||
    !(f === null || (typeof f === "object" && typeof f.name === "string" && typeof f.type === "string" && typeof f.data === "string"))
  ) {
    throw new CliError("bad_handle", "This item is damaged.");
  }
  return o as LocalItem;
}

export async function loadItem(home: string, handleText: string, now = Date.now()): Promise<LocalItem> {
  const { id, key: keyBytes } = parseHandle(handleText);
  const dir = await vaultDir(home);
  const found = await findItem(dir, id);
  if (!found) throw new CliError("expired_handle", "This handle has expired or was forgotten. Open the link again if it still has views left.");
  if (found.expiresAt <= now) {
    await unlink(found.path).catch(() => undefined);
    throw new CliError("expired_handle", "This handle has expired.");
  }
  // Never follow a link planted in place of an item.
  const handle = await open(found.path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let blob: Uint8Array<ArrayBuffer>;
  try {
    blob = new Uint8Array(await handle.readFile());
  } finally {
    await handle.close();
  }
  try {
    const key = await itemKey(keyBytes, "decrypt");
    const plain = await subtle.decrypt(
      { name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: additionalData(id, found.expiresAt) },
      key,
      blob.subarray(12),
    );
    return checkItem(JSON.parse(utf8Decode(new Uint8Array(plain))));
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError("bad_handle", "This handle doesn't match the stored item.");
  } finally {
    keyBytes.fill(0);
  }
}

export async function listItems(home: string): Promise<{ id: string; expiresAt: number }[]> {
  const dir = await vaultDir(home);
  const items: { id: string; expiresAt: number }[] = [];
  for (const name of await files(dir)) {
    const m = ITEM_FILE.exec(name);
    if (m) items.push({ id: m[1] as string, expiresAt: Number(m[2]) });
  }
  return items.sort((a, b) => a.expiresAt - b.expiresAt);
}

/** Forgets one item (by handle or id). Returns whether anything was deleted. */
export async function forgetItem(home: string, handleOrId: string): Promise<boolean> {
  const text = handleOrId.trim();
  const id = ID.test(text) ? text : parseHandle(text).id;
  const dir = await vaultDir(home);
  const found = await findItem(dir, id);
  if (!found) return false;
  await unlink(found.path);
  return true;
}

export async function forgetAll(home: string): Promise<number> {
  const dir = await vaultDir(home);
  let count = 0;
  for (const name of await files(dir)) {
    if (ITEM_FILE.test(name)) {
      await unlink(join(dir, name));
      count++;
    }
  }
  return count;
}
