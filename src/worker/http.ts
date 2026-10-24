import type { ApiError } from "../shared/protocol";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: ApiError,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(code);
  }
}

export type ResponseKind = "page" | "asset" | "api" | "download";

/**
 * Page CSP. Sources are pinned to the app's own files rather than 'self', so nothing else
 * served on this origin (such as Cloudflare's /cdn-cgi/ paths) can run on, or send data
 * from, a page that holds link keys.
 */
const pageCsp = (origin: string): string[] => [
  "default-src 'none'",
  `script-src ${origin}/assets/app.js`,
  `style-src ${origin}/assets/app.css`,
  `img-src ${origin}/assets/logo.svg ${origin}/favicon.svg`,
  "font-src 'none'",
  `connect-src ${origin}/api/v1/`,
  "manifest-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "worker-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "base-uri 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
];

const API_CSP = ["default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"];

const PERMISSIONS_POLICY = [
  "accelerometer=()",
  "autoplay=()",
  "bluetooth=()",
  "browsing-topics=()",
  "camera=()",
  "clipboard-read=()",
  "clipboard-write=(self)",
  "display-capture=()",
  "encrypted-media=()",
  "fullscreen=()",
  "gamepad=()",
  "geolocation=()",
  "gyroscope=()",
  "hid=()",
  "idle-detection=()",
  "local-fonts=()",
  "magnetometer=()",
  "microphone=()",
  "midi=()",
  "payment=()",
  "picture-in-picture=()",
  "publickey-credentials-get=()",
  "screen-wake-lock=()",
  "serial=()",
  "usb=()",
  "xr-spatial-tracking=()",
].join(", ");

export function isLocal(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export interface HardenOptions {
  /** Public pages and discovery files may be indexed; everything else is noindex. */
  indexable?: boolean;
  /** Static, credential-free documents that other origins (such as agent registries) may read. */
  crossOrigin?: boolean;
}

/** Applies the full hardening header set. HSTS and upgrades are skipped only for local development. */
export function harden(response: Response, kind: ResponseKind, url: URL, options: HardenOptions = {}): Response {
  const secure = !isLocal(url.hostname);
  const headers = new Headers(response.headers);
  const csp = kind === "page" ? pageCsp(url.origin) : [...API_CSP];
  if (secure) {
    if (kind === "page") csp.push("upgrade-insecure-requests");
    headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  headers.set("Content-Security-Policy", csp.join("; "));
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", PERMISSIONS_POLICY);
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Embedder-Policy", "require-corp");
  headers.set("Cross-Origin-Resource-Policy", options.crossOrigin ? "cross-origin" : "same-origin");
  if (options.crossOrigin) headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Origin-Agent-Cluster", "?1");
  if (options.indexable) headers.delete("X-Robots-Tag");
  else headers.set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  headers.set("X-DNS-Prefetch-Control", "off");
  headers.set("X-Permitted-Cross-Domain-Policies", "none");
  // Revalidate scripts and styles on every load so security fixes take effect immediately.
  // no-transform keeps proxies (including Cloudflare zone features such as Web Analytics,
  // Email Obfuscation or Rocket Loader) from injecting anything into pages or the bundle.
  headers.set(
    "Cache-Control",
    kind === "asset" ? "no-cache, no-transform" : kind === "page" ? "no-store, no-transform" : "no-store",
  );
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function json<T>(data: T, status = 200): Response {
  return Response.json({ success: true, data }, { status });
}

export function jsonError(status: number, error: ApiError, extra: Record<string, unknown> = {}): Response {
  return Response.json({ success: false, error, ...extra }, { status });
}

/** Reads a request body, refusing anything larger than `max` bytes without buffering it all. */
export async function readCapped(request: Request, max: number): Promise<Uint8Array> {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > max) throw new HttpError(413, "payload_too_large");
  if (!request.body) return new Uint8Array(0);

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new HttpError(413, "payload_too_large");
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

export async function readJson(request: Request, max: number): Promise<unknown> {
  const type = request.headers.get("content-type") ?? "";
  if (!/^application\/json\s*(;|$)/i.test(type)) throw new HttpError(415, "unsupported_media_type");
  const bytes = await readCapped(request, max);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    throw new HttpError(400, "bad_request");
  }
}

/** Logs unexpected errors without request data, tokens or identifiers. */
export function logError(scope: string, error: unknown): void {
  const name = error instanceof Error ? `${error.name}: ${error.message}` : "non-error thrown";
  console.error(`[${scope}] ${name}`);
}
