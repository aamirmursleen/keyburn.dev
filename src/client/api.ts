import type { ApiError, ApiResult } from "../shared/protocol";

export type Outcome<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: ApiError | "network"; attemptsLeft?: number };

function failure(status: number, body: unknown): Outcome<never> {
  const parsed = body as Partial<{ error: ApiError; attemptsLeft: number }> | null;
  const error = typeof parsed?.error === "string" ? parsed.error : "internal";
  return typeof parsed?.attemptsLeft === "number"
    ? { ok: false, status, error, attemptsLeft: parsed.attemptsLeft }
    : { ok: false, status, error };
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export async function post<T>(path: string, body: unknown): Promise<Outcome<T>> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/${path}`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch {
    return { ok: false, status: 0, error: "network" };
  }
  let json: unknown = null;
  try {
    json = await response.json();
  } catch {
    // Non-JSON error page (e.g. an edge error); handled as a generic failure.
  }
  const result = json as ApiResult<T> | null;
  return result?.success ? { ok: true, data: result.data } : failure(response.status, result);
}

/** Uploads ciphertext with progress events (fetch has no upload progress). */
export function uploadCiphertext(
  kind: "secret" | "request",
  id: string,
  token: string,
  data: Uint8Array<ArrayBuffer>,
  onProgress: (fraction: number) => void,
): Promise<Outcome<{ size: number }>> {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", "/api/v1/upload");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-Vault-Box", `${kind}:${id}`);
    xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    xhr.responseType = "json";
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    });
    xhr.addEventListener("load", () => {
      const result = xhr.response as ApiResult<{ size: number }> | null;
      resolve(result?.success ? { ok: true, data: result.data } : failure(xhr.status, result));
    });
    xhr.addEventListener("error", () => resolve({ ok: false, status: 0, error: "network" }));
    xhr.send(data);
  });
}

/** Downloads a ciphertext of known size, reporting progress as it streams in. */
export async function downloadCiphertext(
  kind: "secret" | "request",
  id: string,
  ticket: string,
  size: number,
  onProgress: (fraction: number) => void,
): Promise<Outcome<Uint8Array<ArrayBuffer>>> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/${kind}/download`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ id, ticket }),
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch {
    return { ok: false, status: 0, error: "network" };
  }
  if (!response.ok || !response.body) {
    return failure(response.status, await response.json().catch(() => null));
  }
  const out = new Uint8Array(size);
  let offset = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (offset + value.length > size) return { ok: false, status: 200, error: "internal" };
      out.set(value, offset);
      offset += value.length;
      onProgress(offset / size);
    }
  } catch {
    return { ok: false, status: 0, error: "network" };
  }
  return offset === size ? { ok: true, data: out } : { ok: false, status: 200, error: "network" };
}
