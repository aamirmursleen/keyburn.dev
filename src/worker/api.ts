import { boundId, tokenHash } from "../shared/crypto";
import { LIMITS, PROTOCOL, type ApiError } from "../shared/protocol";
import { HttpError, json, jsonError, logError, readJson } from "./http";
import { clientKey, hashClient, networkKey } from "./ip";
import { quotaName, type Quota, type QuotaLimits } from "./quota";
import {
  encodedSize,
  parseCreateRequest,
  parseCreateSecret,
  parseIdToken,
  parseOpenSecret,
  parseSubmitRequest,
  parseUploadHeaders,
} from "./validate";
import type { Vault, VaultResult } from "./vault";

type Kind = "secret" | "request";
type LimiterName = "create" | "access" | "upload";

interface Ctx {
  request: Request;
  env: Env;
  exec: ExecutionContext;
  client: string;
  /** HMAC of the client's IPv6 /48, or null for IPv4 clients. */
  network: string | null;
  country: string | null;
}

interface Route {
  method: "GET" | "POST" | "PUT";
  limiter: LimiterName;
  handler: (c: Ctx) => Promise<Response>;
}

/** Storage cost charged to quotas for every record, on top of its ciphertext. */
const RECORD_BYTES = 1024;
/** How often (in streamed bytes) a running download re-checks that its file still exists. */
const DOWNLOAD_RECHECK_BYTES = 1024 * 1024;

function vault(env: Env, kind: Kind, id: string): DurableObjectStub<Vault> {
  const ns = env.VAULT as unknown as DurableObjectNamespace<Vault>;
  return ns.get(ns.idFromName(`${kind}:${id}`));
}

function quota(env: Env, name: string): DurableObjectStub<Quota> {
  const ns = env.QUOTA as unknown as DurableObjectNamespace<Quota>;
  return ns.get(ns.idFromName(name));
}

const STATUS: Partial<Record<ApiError, number>> = {
  bad_request: 400,
  not_found: 404,
  conflict: 409,
  wrong_passphrase: 403,
};

function reply<T>(result: VaultResult<T>, status = 200): Response {
  if (result.ok) return json(result.value, status);
  const extra = result.attemptsLeft === undefined ? {} : { attemptsLeft: result.attemptsLeft };
  return jsonError(STATUS[result.error] ?? 500, result.error, extra);
}

function countryOf(request: Request): string | null {
  const cf = (request as Request & { cf?: { country?: unknown } }).cf;
  const value = typeof cf?.country === "string" ? cf.country : request.headers.get("cf-ipcountry");
  return value && /^(?:[A-Z]{2}|T1)$/.test(value) && value !== "XX" ? value : null;
}

/** UTC day for which this isolate already logged that the global budget is used up. */
let capacityLogged = "";

/** A finite, non-negative limit from configuration; falls back to the default if misconfigured. */
function limit(value: unknown, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

/**
 * Charges the client's, its IPv6 network's and the global daily budgets, in that order.
 * Returns a refund for when the operation does not happen after all, so nobody pays for
 * failed attempts. If any budget refuses or fails, the ones already charged are refunded.
 */
async function charge(c: Ctx, creates: number, bytes: number): Promise<() => Promise<void>> {
  const day = new Date().toISOString().slice(0, 10);
  const budgets: [DurableObjectStub<Quota>, QuotaLimits, "client" | "global"][] = [
    [
      quota(c.env, quotaName("ip", c.client, day)),
      { creates: limit(c.env.QUOTA_IP_CREATES_PER_DAY, 100), bytes: limit(c.env.QUOTA_IP_BYTES_PER_DAY, 1_073_741_824) },
      "client",
    ],
  ];
  if (c.network) {
    budgets.push([
      quota(c.env, quotaName("net", c.network, day)),
      { creates: limit(c.env.QUOTA_NET_CREATES_PER_DAY, 400), bytes: limit(c.env.QUOTA_NET_BYTES_PER_DAY, 2_147_483_648) },
      "client",
    ]);
  }
  budgets.push([
    quota(c.env, quotaName("global", "all", day)),
    {
      creates: limit(c.env.QUOTA_GLOBAL_CREATES_PER_DAY, 50_000),
      bytes: limit(c.env.QUOTA_GLOBAL_BYTES_PER_DAY, 107_374_182_400),
    },
    "global",
  ]);

  const done: DurableObjectStub<Quota>[] = [];
  const refund = async (): Promise<void> => {
    await Promise.all(done.map((budget) => budget.refund(creates, bytes))).catch((error: unknown) =>
      logError("quota:refund", error),
    );
  };
  for (const [budget, limits, scope] of budgets) {
    let ok: boolean;
    try {
      ok = await budget.consume(creates, bytes, limits);
    } catch (error) {
      // Earlier charges must not leak when a counter is unavailable.
      await refund();
      throw error;
    }
    if (!ok) {
      await refund();
      if (scope === "client") throw new HttpError(429, "quota_exceeded");
      // The shared budget is used up: everyone is refused until 00:00 UTC, so tell the
      // operator once per isolate per day, and tell users it isn't their network.
      if (capacityLogged !== day) {
        capacityLogged = day;
        logError("quota", new Error(`global daily budget reached on ${day}; creation paused until 00:00 UTC`));
      }
      throw new HttpError(429, "capacity");
    }
    done.push(budget);
  }
  return refund;
}

/** Runs `operation` against a charge that is refunded if it fails or throws. */
async function charged<T>(
  c: Ctx,
  creates: number,
  bytes: number,
  operation: () => Promise<VaultResult<T>>,
): Promise<VaultResult<T>> {
  const refund = await charge(c, creates, bytes);
  try {
    const result = await operation();
    if (!result.ok) await refund();
    return result;
  } catch (error) {
    await refund();
    throw error;
  }
}

// ---- secrets -----------------------------------------------------------------

async function createSecret(c: Ctx): Promise<Response> {
  const input = parseCreateSecret(await readJson(c.request, LIMITS.jsonBodyMaxBytes));
  // The id must be bound to the meta token, so an id alone can't be used to claim or probe a record.
  if (input.id !== (await boundId("secret", input.metaHash))) throw new HttpError(400, "bad_request");
  // File bytes are charged when they are actually uploaded, not when declared.
  const stub = vault(c.env, "secret", input.id);
  return reply(await charged(c, 1, encodedSize(input.ct) + RECORD_BYTES, () => stub.createSecret(input)), 201);
}

async function secretMeta(c: Ctx): Promise<Response> {
  const { id, metaToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "metaToken");
  return reply(await vault(c.env, "secret", id).secretMeta(await tokenHash(metaToken)));
}

async function openSecret(c: Ctx): Promise<Response> {
  const { id, metaToken, readToken } = parseOpenSecret(await readJson(c.request, LIMITS.jsonBodyMaxBytes));
  const stub = vault(c.env, "secret", id);
  return reply(await stub.openSecret(await tokenHash(metaToken), await tokenHash(readToken), c.country));
}

async function secretStatus(c: Ctx): Promise<Response> {
  const { id, manageToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "manageToken");
  return reply(await vault(c.env, "secret", id).secretStatus(await tokenHash(manageToken)));
}

async function revokeSecret(c: Ctx): Promise<Response> {
  const { id, manageToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "manageToken");
  return reply(await vault(c.env, "secret", id).revokeSecret(await tokenHash(manageToken)));
}

// ---- requests ----------------------------------------------------------------

async function createRequest(c: Ctx): Promise<Response> {
  const input = parseCreateRequest(await readJson(c.request, LIMITS.jsonBodyMaxBytes));
  // The id must be bound to the submit token, so an id alone can't be used to claim or probe a record.
  if (input.id !== (await boundId("request", input.submitHash))) throw new HttpError(400, "bad_request");
  const stub = vault(c.env, "request", input.id);
  const bytes = (input.note ? encodedSize(input.note.ct) : 0) + RECORD_BYTES;
  return reply(await charged(c, 1, bytes, () => stub.createRequest(input)), 201);
}

async function requestInfo(c: Ctx): Promise<Response> {
  const { id, submitToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "submitToken");
  return reply(await vault(c.env, "request", id).requestInfo(await tokenHash(submitToken)));
}

async function submitRequest(c: Ctx): Promise<Response> {
  const { id, submitToken, ...input } = parseSubmitRequest(await readJson(c.request, LIMITS.jsonBodyMaxBytes));
  const stub = vault(c.env, "request", id);
  const hash = await tokenHash(submitToken);
  const bytes = encodedSize(input.ct) + RECORD_BYTES;
  return reply(await charged(c, 1, bytes, () => stub.submitRequest(hash, input, c.country)), 201);
}

async function inboxStatus(c: Ctx): Promise<Response> {
  const { id, inboxToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "inboxToken");
  return reply(await vault(c.env, "request", id).inboxStatus(await tokenHash(inboxToken)));
}

async function openInbox(c: Ctx): Promise<Response> {
  const { id, inboxToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "inboxToken");
  return reply(await vault(c.env, "request", id).openInbox(await tokenHash(inboxToken)));
}

async function revokeRequest(c: Ctx): Promise<Response> {
  const { id, inboxToken } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "inboxToken");
  return reply(await vault(c.env, "request", id).revokeRequest(await tokenHash(inboxToken)));
}

// ---- files -------------------------------------------------------------------

async function upload(c: Ctx): Promise<Response> {
  const { kind, id, token, length } = parseUploadHeaders(c.request.headers);
  if (c.request.headers.get("content-type") !== "application/octet-stream") {
    throw new HttpError(415, "unsupported_media_type");
  }
  const body = c.request.body;
  if (!body) throw new HttpError(400, "bad_request");

  const stub = vault(c.env, kind, id);
  const hash = await tokenHash(token);
  const begin = await stub.beginUpload(hash, length);
  if (!begin.ok) return reply(begin);
  const { r2Key } = begin.value;

  // Store first and charge only once every byte has arrived, so an upload that is slow
  // or never finishes holds no quota. Any failure discards just this attempt's object.
  let stored: R2Object | null = null;
  try {
    // FixedLengthStream fails the upload if the body is shorter or longer than declared.
    stored = await c.env.FILES.put(r2Key, body.pipeThrough(new FixedLengthStream(length)));
  } catch {
    stored = null;
  }
  if (!stored || stored.size !== length) {
    await stub.abortUpload(r2Key);
    throw new HttpError(400, "bad_request");
  }
  const result = await charged(c, 0, length, () => stub.completeUpload(hash, r2Key, length)).catch(
    async (error: unknown) => {
      await stub.abortUpload(r2Key);
      throw error;
    },
  );
  if (!result.ok) await stub.abortUpload(r2Key);
  return reply(result);
}

async function download(c: Ctx, kind: Kind): Promise<Response> {
  const { id, ticket } = parseIdToken(await readJson(c.request, LIMITS.jsonBodyMaxBytes), "ticket");
  const stub = vault(c.env, kind, id);
  const hash = await tokenHash(ticket);
  const granted = await stub.redeemTicket(hash);
  if (!granted.ok) return reply(granted);

  const object = await c.env.FILES.get(granted.value.r2Key);
  if (!object) return jsonError(404, "not_found");

  const { readable, writable } = new FixedLengthStream(object.size);
  const r2Key = granted.value.r2Key;
  // Re-check the file every few MiB, so revoking, expiry and lockout also cut off a
  // download that is already streaming (the R2 read itself is not tied to the Vault).
  let unchecked = 0;
  const guard = new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      unchecked += chunk.byteLength;
      if (unchecked >= DOWNLOAD_RECHECK_BYTES) {
        unchecked = 0;
        if (!(await stub.downloadAllowed(r2Key))) throw new Error("download no longer allowed");
      }
      controller.enqueue(chunk);
    },
  });
  // Mark the ticket used only once the whole ciphertext has been delivered.
  c.exec.waitUntil(
    object.body
      .pipeThrough(guard)
      .pipeTo(writable)
      .then(() => stub.ticketDone(hash))
      .catch((error: unknown) => logError("download", error)),
  );
  return new Response(readable, {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="encrypted.bin"',
    },
  });
}

// ---- routing -------------------------------------------------------------------

const ROUTES: Record<string, Route> = {
  "/api/v1/secret/create": { method: "POST", limiter: "create", handler: createSecret },
  "/api/v1/secret/meta": { method: "POST", limiter: "access", handler: secretMeta },
  "/api/v1/secret/open": { method: "POST", limiter: "access", handler: openSecret },
  "/api/v1/secret/status": { method: "POST", limiter: "access", handler: secretStatus },
  "/api/v1/secret/revoke": { method: "POST", limiter: "access", handler: revokeSecret },
  "/api/v1/secret/download": { method: "POST", limiter: "access", handler: (c) => download(c, "secret") },
  "/api/v1/request/create": { method: "POST", limiter: "create", handler: createRequest },
  "/api/v1/request/info": { method: "POST", limiter: "access", handler: requestInfo },
  "/api/v1/request/submit": { method: "POST", limiter: "create", handler: submitRequest },
  "/api/v1/request/status": { method: "POST", limiter: "access", handler: inboxStatus },
  "/api/v1/request/open": { method: "POST", limiter: "access", handler: openInbox },
  "/api/v1/request/revoke": { method: "POST", limiter: "access", handler: revokeRequest },
  "/api/v1/request/download": { method: "POST", limiter: "access", handler: (c) => download(c, "request") },
  "/api/v1/upload": { method: "PUT", limiter: "upload", handler: upload },
  // For monitors and the API catalog (/.well-known/api-catalog). Touches no storage.
  "/api/v1/health": { method: "GET", limiter: "access", handler: async () => json({ status: "ok", protocol: PROTOCOL }) },
};

function limiter(env: Env, name: LimiterName): RateLimit {
  return name === "create" ? env.RL_CREATE : name === "upload" ? env.RL_UPLOAD : env.RL_ACCESS;
}

/** Browsers always send these on fetch(); anything cross-site is refused outright. */
function assertSameOrigin(request: Request, url: URL): void {
  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin") throw new HttpError(403, "forbidden");
  const origin = request.headers.get("origin");
  if (origin && origin !== url.origin) throw new HttpError(403, "forbidden");
}

export async function handleApi(request: Request, env: Env, exec: ExecutionContext, url: URL): Promise<Response> {
  const route = ROUTES[url.pathname];
  if (!route) throw new HttpError(404, "not_found");
  if (request.method !== route.method) {
    const res = jsonError(405, "method_not_allowed");
    res.headers.set("Allow", route.method);
    return res;
  }
  assertSameOrigin(request, url);

  const client = await hashClient(env.IP_HASH_SECRET, clientKey(request));
  const { success } = await limiter(env, route.limiter).limit({ key: client });
  if (!success) throw new HttpError(429, "rate_limited");
  const net = networkKey(request);
  const network = net ? await hashClient(env.IP_HASH_SECRET, net) : null;

  return route.handler({ request, env, exec, client, network, country: countryOf(request) });
}
