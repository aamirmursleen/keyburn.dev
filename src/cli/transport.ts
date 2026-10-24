// The HTTP transport osss uses instead of Node's fetch(). fetch() decompresses responses
// automatically, which runs the server's bytes through zlib's Brotli and gzip decoders (the
// path of CVE-2026-111497) and reuses keep-alive sockets (CVE-2026-105481). This transport asks
// for uncompressed data, refuses any compressed or redirected response before reading its
// body, never decompresses, and uses a new connection for every request.

import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import type { Fetch } from "./http";

function toHeaders(res: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(res.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  }
  return headers;
}

export const plainFetch: Fetch = (url, init) =>
  new Promise<Response>((resolve, reject) => {
    const target = new URL(url);
    const body = init.body;
    if (body !== undefined && body !== null && typeof body !== "string" && !(body instanceof Uint8Array)) {
      reject(new TypeError("Unsupported request body."));
      return;
    }
    const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined), "accept-encoding": "identity" };
    if (body !== undefined && body !== null) headers["content-length"] = String(typeof body === "string" ? Buffer.byteLength(body) : body.byteLength);
    const send = target.protocol === "https:" ? httpsRequest : target.protocol === "http:" ? httpRequest : null;
    if (!send) {
      reject(new TypeError("Unsupported protocol."));
      return;
    }
    const req = send(target, { method: init.method ?? "GET", headers, agent: false, signal: init.signal ?? undefined }, (res) => {
      const status = res.statusCode ?? 0;
      const encoding = (res.headers["content-encoding"] ?? "identity").trim().toLowerCase();
      if (encoding !== "identity" || (status >= 300 && status < 400) || status < 200) {
        // Never read a compressed or redirected body: drop the connection instead.
        res.destroy();
        reject(new TypeError(encoding !== "identity" ? "Compressed response refused." : "Redirect refused."));
        return;
      }
      const empty = status === 204 || init.method === "HEAD";
      resolve(new Response(empty ? null : (Readable.toWeb(res) as ReadableStream<Uint8Array>), { status, headers: toHeaders(res) }));
    });
    req.on("error", reject);
    req.end(body ?? undefined);
  });
