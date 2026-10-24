import { handleApi } from "./api";
import { HttpError, harden, isLocal, jsonError, logError } from "./http";
import { asksForHtml, prefersMarkdown } from "./negotiate";

export { Quota } from "./quota";
export { Vault } from "./vault";

interface Page {
  file: string;
  /** A Markdown version for agents, served for Accept: text/markdown. */
  markdown?: string;
  /** Public pages may be indexed; the pages that open links never are. */
  indexable?: boolean;
  /**
   * A page that opens a link. Agents fetch these links with curl or a fetch tool, which never
   * sends the key after "#", so clients that don't ask for HTML get the Markdown, which says
   * how to open the link.
   */
  opensLink?: boolean;
}

/** Exact allowlist: anything not listed here is a 404. */
const PAGES: Record<string, Page> = {
  "/": { file: "/index.html", markdown: "/md/index.md", indexable: true },
  "/request": { file: "/request.html", markdown: "/md/request.md", indexable: true },
  "/security": { file: "/security.html", markdown: "/md/security.md", indexable: true },
  "/agents": { file: "/agents.html", markdown: "/md/agents.md", indexable: true },
  "/s": { file: "/s.html", markdown: "/md/s.md", opensLink: true },
  "/m": { file: "/m.html", markdown: "/md/m.md", opensLink: true },
  "/r": { file: "/r.html", markdown: "/md/r.md", opensLink: true },
  "/i": { file: "/i.html", markdown: "/md/i.md", opensLink: true },
};

const MARKDOWN = "text/markdown; charset=utf-8";
const JSON_TYPE = "application/json; charset=utf-8";

/** Machine-readable files for crawlers and agents: published path -> stored file and type. */
const DOCUMENTS: Record<string, { file: string; type: string; crossOrigin?: boolean }> = {
  "/robots.txt": { file: "/robots.txt", type: "text/plain; charset=utf-8" },
  "/sitemap.xml": { file: "/sitemap.xml", type: "application/xml; charset=utf-8" },
  "/llms.txt": { file: "/llms.txt", type: MARKDOWN, crossOrigin: true },
  "/auth.md": { file: "/auth.md", type: MARKDOWN, crossOrigin: true },
  "/index.md": { file: "/md/index.md", type: MARKDOWN, crossOrigin: true },
  "/request.md": { file: "/md/request.md", type: MARKDOWN, crossOrigin: true },
  "/security.md": { file: "/md/security.md", type: MARKDOWN, crossOrigin: true },
  "/agents.md": { file: "/md/agents.md", type: MARKDOWN, crossOrigin: true },
  "/openapi.json": { file: "/openapi.json", type: JSON_TYPE, crossOrigin: true },
  "/.well-known/api-catalog": {
    file: "/.well-known/api-catalog.json",
    type: 'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"',
    crossOrigin: true,
  },
  "/.well-known/ai-catalog.json": { file: "/.well-known/ai-catalog.json", type: JSON_TYPE, crossOrigin: true },
  "/.well-known/agent-skills/index.json": { file: "/.well-known/agent-skills/index.json", type: JSON_TYPE, crossOrigin: true },
  "/.well-known/agent-skills/osss/SKILL.md": { file: "/.well-known/agent-skills/osss/SKILL.md", type: MARKDOWN, crossOrigin: true },
};

/** Advertised on public pages so agents can find the machine-readable descriptions (RFC 8288). */
const DISCOVERY_LINKS = [
  '</.well-known/api-catalog>; rel="api-catalog"',
  '</openapi.json>; rel="service-desc"; type="application/vnd.oai.openapi+json"',
  '</agents>; rel="service-doc"; type="text/html"',
  '</llms.txt>; rel="describedby"; type="text/markdown"',
  '</.well-known/ai-catalog.json>; rel="ai-catalog"; type="application/json"',
];

/** The first hosts, before keyburn.dev. */
const LEGACY_HOSTS = new Set(["secret.nafran.com", "secrets.nafran.com"]);

const ROOT_FILES = new Set(["/favicon.svg", "/.well-known/security.txt"]);
const ASSET = /^\/assets\/[a-z0-9-]+\.(?:js|css|svg)$/;
/** Self-hosted web fonts (Poppins, JetBrains Mono; SIL Open Font License). */
const FONT = /^\/assets\/fonts\/[a-z0-9-]+\.woff2$/;
/** The KeyBurn logo: animated and still WebP, favicon and home-screen icon, the fire loop and its mask. */
const BRAND = /^\/assets\/brand\/[a-z0-9-]+\.(webp|png|mp4|webm|svg)$/;
const BRAND_TYPES: Record<string, string> = {
  webp: "image/webp",
  png: "image/png",
  mp4: "video/mp4",
  webm: "video/webm",
  svg: "image/svg+xml",
};
/** The agent tool: versioned files only (each pinned by its SHA-256), and SHA256SUMS. */
const CLI_FILE = /^\/cli\/(?:osss-\d{1,3}\.\d{1,3}\.\d{1,3}\.mjs|SHA256SUMS)$/;

function fetchAsset(env: Env, path: string, request: Request, conditional: boolean, method = request.method): Promise<Response> {
  const headers = new Headers();
  const etag = request.headers.get("if-none-match");
  if (conditional && etag) headers.set("If-None-Match", etag);
  return env.ASSETS.fetch(new Request(new URL(path, "https://assets.local"), { method, headers }));
}

/**
 * Answers a single byte range of a small file (Safari only plays video that supports ranges).
 * Anything but one well-formed range gets the whole file.
 */
async function byteRange(file: Response, range: string, type: string, method: string): Promise<Response> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const total = bytes.byteLength;
  const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
  const headers = new Headers({ "Content-Type": type, "Accept-Ranges": "bytes" });
  const etag = file.headers.get("etag");
  if (etag) headers.set("ETag", etag);
  if (!m || (m[1] === "" && m[2] === "")) return new Response(method === "HEAD" ? null : bytes, { status: 200, headers });
  let start: number;
  let end: number;
  if (m[1] === "") {
    start = Math.max(0, total - Number(m[2]));
    end = total - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === "" ? total - 1 : Math.min(Number(m[2]), total - 1);
  }
  if (start >= total || start > end) {
    headers.set("Content-Range", `bytes */${total}`);
    return new Response(null, { status: 416, headers });
  }
  headers.set("Content-Range", `bytes ${start}-${end}/${total}`);
  return new Response(method === "HEAD" ? null : bytes.slice(start, end + 1), { status: 206, headers });
}

function withType(response: Response, type: string): Response {
  const headers = new Headers(response.headers);
  headers.set("Content-Type", type);
  return new Response(response.body, { status: response.status, headers });
}

async function servePage(request: Request, env: Env, url: URL, page: Page): Promise<Response> {
  const accept = request.headers.get("accept");
  if (page.markdown && (prefersMarkdown(accept) || (page.opensLink && !asksForHtml(accept)))) {
    const file = await fetchAsset(env, page.markdown, request, false, "GET");
    if (file.ok) {
      const text = await file.text();
      const headers = new Headers({ "Content-Type": MARKDOWN, Vary: "Accept", "x-markdown-tokens": String(Math.ceil(text.length / 4)) });
      const body = request.method === "HEAD" ? null : text;
      return harden(new Response(body, { headers }), "asset", url, { indexable: page.indexable, crossOrigin: page.indexable });
    }
    await file.body?.cancel();
  }
  const response = harden(await fetchAsset(env, page.file, request, false), "page", url, { indexable: page.indexable });
  if (page.markdown) response.headers.append("Vary", "Accept");
  if (page.indexable) {
    const alternate = `<${url.pathname === "/" ? "/index" : url.pathname}.md>; rel="alternate"; type="text/markdown"`;
    response.headers.set("Link", [...DISCOVERY_LINKS, alternate].join(", "));
  }
  return response;
}

async function serveStatic(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return harden(new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } }), "page", url);
  }
  const page = PAGES[url.pathname];
  if (page) return servePage(request, env, url, page);

  const doc = DOCUMENTS[url.pathname];
  if (doc) {
    const file = await fetchAsset(env, doc.file, request, true);
    if (file.status === 200 || file.status === 304) {
      return harden(withType(file, doc.type), "asset", url, { indexable: true, crossOrigin: doc.crossOrigin });
    }
    await file.body?.cancel();
  }
  if (CLI_FILE.test(url.pathname)) {
    const file = await fetchAsset(env, url.pathname, request, true);
    // Served as plain text so a browser never runs it; people save it and run it with Node.
    if (file.status === 200 || file.status === 304) return harden(withType(file, "text/plain; charset=utf-8"), "asset", url);
    await file.body?.cancel();
  }
  if (FONT.test(url.pathname)) {
    const font = await fetchAsset(env, url.pathname, request, true);
    if (font.status === 200 || font.status === 304) return harden(withType(font, "font/woff2"), "asset", url);
    await font.body?.cancel();
  }
  const brand = BRAND.exec(url.pathname);
  if (brand) {
    const type = BRAND_TYPES[brand[1] as string] as string;
    const range = brand[1] === "mp4" || brand[1] === "webm" ? request.headers.get("range") : null;
    const file = await fetchAsset(env, url.pathname, request, !range, range ? "GET" : request.method);
    if (file.status === 200 && range) return harden(await byteRange(file, range, type, request.method), "asset", url);
    if (file.status === 200 || file.status === 304) return harden(withType(file, type), "asset", url);
    await file.body?.cancel();
  }
  if (ASSET.test(url.pathname) || ROOT_FILES.has(url.pathname)) {
    const asset = await fetchAsset(env, url.pathname, request, true);
    if (asset.status === 200 || asset.status === 304) return harden(asset, "asset", url);
    await asset.body?.cancel();
  }
  const missing = await fetchAsset(env, "/404.html", request, false);
  return harden(new Response(missing.body, { status: 404, headers: missing.headers }), "page", url);
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url);
    // Everything people visit lives on keyburn.dev. Browsers keep the "#..." part of a link
    // across a redirect, so links made on the first hosts still open there. Those hosts keep
    // their API and CLI files for the osss versions and links that name them.
    const legacyPage = LEGACY_HOSTS.has(url.hostname) && !url.pathname.startsWith("/api/") && !url.pathname.startsWith("/cli/");
    if (url.hostname === "www.keyburn.dev" || legacyPage) {
      url.hostname = "keyburn.dev";
      url.protocol = "https:";
      url.port = "";
      return harden(Response.redirect(url.toString(), 301), "api", url);
    }
    if (url.protocol === "http:" && !isLocal(url.hostname)) {
      url.protocol = "https:";
      return harden(Response.redirect(url.toString(), 301), "api", url);
    }

    try {
      if (url.pathname.startsWith("/api/")) {
        return harden(await handleApi(request, env, ctx, url), "api", url);
      }
      return await serveStatic(request, env, url);
    } catch (error) {
      if (error instanceof HttpError) {
        return harden(jsonError(error.status, error.code, error.extra), "api", url);
      }
      logError("worker", error);
      return harden(jsonError(500, "internal"), "api", url);
    }
  },
} satisfies ExportedHandler<Env>;
