import type { Bytes } from "../shared/encoding";
import type { ApiError } from "../shared/protocol";

export type Fetch = (url: string, init: RequestInit) => Promise<Response>;

export type Outcome<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: ApiError | "network"; attemptsLeft?: number };

/** API responses are small; anything larger is not from this service. */
const JSON_LIMIT = 1024 * 1024;
const JSON_TIMEOUT_MS = 30_000;
const TRANSFER_TIMEOUT_MS = 10 * 60_000;
const API_ERRORS = new Set<string>([
  "bad_request",
  "unsupported_media_type",
  "payload_too_large",
  "forbidden",
  "method_not_allowed",
  "not_found",
  "conflict",
  "wrong_passphrase",
  "rate_limited",
  "quota_exceeded",
  "capacity",
  "unavailable",
  "internal",
]);

async function readCapped(response: Response, limit: number): Promise<Bytes | null> {
  if (!response.body) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function failure(status: number, body: unknown): Outcome<never> {
  const parsed = body && typeof body === "object" ? (body as { error?: unknown; attemptsLeft?: unknown }) : {};
  const error = typeof parsed.error === "string" && API_ERRORS.has(parsed.error) ? (parsed.error as ApiError) : "internal";
  const attemptsLeft = Number.isSafeInteger(parsed.attemptsLeft) ? (parsed.attemptsLeft as number) : undefined;
  return attemptsLeft === undefined ? { ok: false, status, error } : { ok: false, status, error, attemptsLeft };
}

/**
 * Talks to one trusted origin. Never follows redirects (a compromised server must not be able
 * to send requests elsewhere), caps response sizes and times out.
 */
export class Api {
  constructor(
    readonly origin: string,
    private readonly fetchFn: Fetch = (url, init) => fetch(url, init),
  ) {}

  async post<T>(path: string, body: unknown): Promise<Outcome<T>> {
    let response: Response;
    try {
      response = await this.fetchFn(`${this.origin}/api/v1/${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(JSON_TIMEOUT_MS),
      });
    } catch {
      return { ok: false, status: 0, error: "network" };
    }
    let json: unknown = null;
    try {
      const raw = await readCapped(response, JSON_LIMIT);
      json = raw ? JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw)) : null;
    } catch {
      json = null;
    }
    const result = json && typeof json === "object" ? (json as { success?: unknown; data?: unknown }) : null;
    if (response.ok && result?.success === true && "data" in result) return { ok: true, data: result.data as T };
    return failure(response.status, json);
  }

  async upload(kind: "secret" | "request", id: string, token: string, data: Bytes): Promise<Outcome<{ size: number }>> {
    let response: Response;
    try {
      response = await this.fetchFn(`${this.origin}/api/v1/upload`, {
        method: "PUT",
        headers: {
          "content-type": "application/octet-stream",
          "x-vault-box": `${kind}:${id}`,
          authorization: `Bearer ${token}`,
        },
        body: data,
        redirect: "error",
        signal: AbortSignal.timeout(TRANSFER_TIMEOUT_MS),
      });
    } catch {
      return { ok: false, status: 0, error: "network" };
    }
    let json: unknown = null;
    try {
      const raw = await readCapped(response, JSON_LIMIT);
      json = raw ? JSON.parse(new TextDecoder().decode(raw)) : null;
    } catch {
      json = null;
    }
    const result = json && typeof json === "object" ? (json as { success?: unknown; data?: unknown }) : null;
    if (response.ok && result?.success === true) return { ok: true, data: result.data as { size: number } };
    return failure(response.status, json);
  }

  /** Downloads exactly `size` bytes of ciphertext; anything shorter or longer is an error. */
  async download(kind: "secret" | "request", id: string, ticket: string, size: number): Promise<Outcome<Bytes>> {
    let response: Response;
    try {
      response = await this.fetchFn(`${this.origin}/api/v1/${kind}/download`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id, ticket }),
        redirect: "error",
        signal: AbortSignal.timeout(TRANSFER_TIMEOUT_MS),
      });
    } catch {
      return { ok: false, status: 0, error: "network" };
    }
    if (!response.ok) {
      let json: unknown = null;
      try {
        const raw = await readCapped(response, JSON_LIMIT);
        json = raw ? JSON.parse(new TextDecoder().decode(raw)) : null;
      } catch {
        json = null;
      }
      return failure(response.status, json);
    }
    try {
      const data = await readCapped(response, size);
      if (!data || data.byteLength !== size) return { ok: false, status: response.status, error: "network" };
      return { ok: true, data };
    } catch {
      return { ok: false, status: 0, error: "network" };
    }
  }
}
