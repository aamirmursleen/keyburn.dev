import { env } from "cloudflare:workers";
import {
  createExecutionContext,
  runDurableObjectAlarm,
  runInDurableObject,
  waitOnExecutionContext,
} from "cloudflare:test";
import worker from "../src/worker/index";
import { b64urlDecode, b64urlEncode, type Bytes } from "../src/shared/encoding";
import {
  aad,
  newRequester,
  openPayload,
  randomBytes,
  requestAddress,
  sealFile,
  sealPayload,
  secretAddress,
  secretKeys,
  senderKeys,
  inboxToken,
  tokenHash,
} from "../src/shared/crypto";
import {
  LIMITS,
  type CreateRequestInput,
  type CreateSecretInput,
  type KdfParams,
  type SubmitRequestInput,
} from "../src/shared/protocol";
import type { Vault } from "../src/worker/vault";

export const ORIGIN = "https://secret.onesmartsheep.com";

let ipCounter = 0;

/** A distinct client IP per call keeps rate limits and quotas independent between tests. */
export function freshIp(): string {
  ipCounter++;
  return `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}`;
}

export interface ApiResponse {
  status: number;
  body: any;
  headers: Headers;
}

export async function call(
  path: string,
  body: unknown,
  opts: { ip?: string; headers?: Record<string, string>; method?: string; raw?: BodyInit } = {},
): Promise<ApiResponse> {
  const method = opts.method ?? "POST";
  const ctx = createExecutionContext();
  const request = new Request(`${ORIGIN}/api/v1/${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        "cf-connecting-ip": opts.ip ?? freshIp(),
        "sec-fetch-site": "same-origin",
        ...opts.headers,
      },
      body: method === "GET" || method === "HEAD" ? undefined : (opts.raw ?? JSON.stringify(body)),
  }) as Request<unknown, IncomingRequestCfProperties>;
  const res = await worker.fetch(request, env, ctx);
  const type = res.headers.get("content-type") ?? "";
  const parsed = type.includes("application/json") ? await res.json() : new Uint8Array(await res.arrayBuffer());
  // Let waitUntil work (e.g. marking a download complete) settle before asserting.
  await waitOnExecutionContext(ctx);
  return { status: res.status, body: parsed, headers: res.headers };
}

export async function upload(kind: "secret" | "request", id: string, token: string, bytes: Uint8Array, ip = freshIp()) {
  return call("upload", null, {
    method: "PUT",
    ip,
    raw: bytes,
    headers: {
      "content-type": "application/octet-stream",
      "content-length": String(bytes.length),
      "x-vault-box": `${kind}:${id}`,
      authorization: `Bearer ${token}`,
    },
  });
}

export function vaultStub(kind: "secret" | "request", id: string): DurableObjectStub<Vault> {
  const ns = env.VAULT as unknown as DurableObjectNamespace<Vault>;
  return ns.get(ns.idFromName(`${kind}:${id}`));
}

/** Rewrites stored timestamps so time-based transitions can be tested without waiting. */
export async function shiftTime(kind: "secret" | "request", id: string, ms: number): Promise<void> {
  await runInDurableObject(vaultStub(kind, id), (_instance: Vault, state: DurableObjectState) => {
    for (const [key, value] of state.storage.kv.list()) {
      state.storage.kv.put(key, shift(value, ms));
    }
  });
}

function shift(value: unknown, ms: number): unknown {
  if (Array.isArray(value)) return value.map((v) => shift(v, ms));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = ["expiresAt", "openUntil", "purgeAt", "uploadUntil", "until"].includes(k) && typeof v === "number" ? v - ms : shift(v, ms);
    }
    return out;
  }
  return value;
}

/** The R2 key of the stored ciphertext file, read straight from the vault's storage. */
export async function fileKeyOf(kind: "secret" | "request", id: string): Promise<string> {
  const key = await runInDurableObject(vaultStub(kind, id), (_i: Vault, state: DurableObjectState) => {
    const file = state.storage.kv.get<{ r2Key: string }>("file");
    return file?.r2Key ?? null;
  });
  if (!key) throw new Error("no file state");
  return key;
}

/** Polls until `check` passes; background alarms (e.g. R2 cleanup) finish asynchronously. */
export async function eventually(check: () => Promise<boolean>, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error("condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

export async function runAlarm(kind: "secret" | "request", id: string): Promise<boolean> {
  return runDurableObjectAlarm(vaultStub(kind, id));
}

export async function storedKeys(kind: "secret" | "request", id: string): Promise<string[]> {
  return runInDurableObject(vaultStub(kind, id), (_i: Vault, state: DurableObjectState) =>
    [...state.storage.kv.list()].map(([key]) => key),
  );
}

export interface MadeSecret {
  id: string;
  S: Bytes;
  metaToken: string;
  readToken: string;
  manageToken: string;
  textKey: CryptoKey;
  fileKey: CryptoKey;
  input: CreateSecretInput;
  res: ApiResponse;
  file: { data: Bytes; ct: Bytes; iv: string } | null;
}

export async function makeSecret(
  opts: { text?: string; passphrase?: string; maxViews?: number; expiresIn?: number; file?: Bytes; ip?: string } = {},
): Promise<MadeSecret> {
  const S = randomBytes(32);
  const { id, metaToken } = await secretAddress(S);
  const kdf: KdfParams | null = opts.passphrase
    ? { alg: "PBKDF2-SHA256", iterations: LIMITS.pbkdf2MinIterations, salt: b64urlEncode(randomBytes(16)) }
    : null;
  const keys = await secretKeys(S, kdf && opts.passphrase ? { passphrase: opts.passphrase, kdf } : null);
  const sealedFile = opts.file ? await sealFile(keys.fileKey, aad.secretFile(id), opts.file) : null;
  const fileMeta = opts.file ? { name: "keys.env", type: "text/plain", size: opts.file.length } : null;
  const sealed = await sealPayload(keys.textKey, aad.secretText(id), { v: 1, text: opts.text ?? "hunter2", file: fileMeta });
  const manageToken = b64urlEncode(randomBytes(32));
  const input: CreateSecretInput = {
    id,
    metaHash: await tokenHash(metaToken),
    readHash: await tokenHash(keys.readToken),
    manageHash: await tokenHash(manageToken),
    iv: sealed.iv,
    ct: sealed.ct,
    expiresIn: opts.expiresIn ?? 3600,
    maxViews: opts.maxViews ?? 1,
    kdf,
    file: sealedFile ? { size: sealedFile.ct.length, iv: sealedFile.iv } : null,
  };
  const res = await call("secret/create", input, { ip: opts.ip });
  return {
    id,
    S,
    metaToken,
    readToken: keys.readToken,
    manageToken,
    textKey: keys.textKey,
    fileKey: keys.fileKey,
    input,
    res,
    file: opts.file && sealedFile ? { data: opts.file, ct: sealedFile.ct, iv: sealedFile.iv } : null,
  };
}

export async function decryptText(secret: MadeSecret, body: { iv: string; ct: string }): Promise<string> {
  return (await openPayload(secret.textKey, aad.secretText(secret.id), body)).text;
}

export interface MadeRequest {
  id: string;
  Q: Bytes;
  pub: Bytes;
  d: Bytes;
  submitToken: string;
  inboxToken: string;
  noteKey: CryptoKey;
  input: CreateRequestInput;
  res: ApiResponse;
}

export async function makeRequest(opts: { note?: string; expiresIn?: number } = {}): Promise<MadeRequest> {
  const requester = await newRequester();
  const addr = await requestAddress(requester.Q);
  const inbox = await inboxToken(requester.Q, requester.d);
  const note = opts.note
    ? await sealPayload(addr.noteKey, aad.requestNote(addr.id), { v: 1, text: opts.note, file: null })
    : null;
  const input: CreateRequestInput = {
    id: addr.id,
    submitHash: await tokenHash(addr.submitToken),
    inboxHash: await tokenHash(inbox),
    pub: b64urlEncode(requester.pub),
    note,
    expiresIn: opts.expiresIn ?? 86400,
  };
  const res = await call("request/create", input);
  return { ...requester, id: addr.id, submitToken: addr.submitToken, inboxToken: inbox, noteKey: addr.noteKey, input, res };
}

export async function makeSubmission(req: MadeRequest, text: string, file?: Bytes) {
  const keys = await senderKeys(req.pub, req.Q, req.id);
  const sealedFile = file ? await sealFile(keys.fileKey, aad.requestFile(req.id), file) : null;
  const sealed = await sealPayload(keys.textKey, aad.requestText(req.id), {
    v: 1,
    text,
    file: file ? { name: "creds.txt", type: "text/plain", size: file.length } : null,
  });
  const input: SubmitRequestInput = {
    id: req.id,
    submitToken: req.submitToken,
    ephPub: b64urlEncode(keys.ephPub),
    iv: sealed.iv,
    ct: sealed.ct,
    file: sealedFile ? { size: sealedFile.ct.length, iv: sealedFile.iv } : null,
  };
  return { input, sealedFile, keys };
}

export { b64urlDecode, b64urlEncode, randomBytes, tokenHash };
