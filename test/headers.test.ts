import { env } from "cloudflare:workers";
import { createExecutionContext } from "cloudflare:test";
import worker from "../src/worker/index";
import { describe, expect, it } from "vitest";
import { call } from "./helpers";

const fetchPage = (url: string, init?: RequestInit) =>
  worker.fetch(new Request(url, init) as Request<unknown, IncomingRequestCfProperties>, env, createExecutionContext());

function expectHardened(headers: Headers, { indexable = false, crossOrigin = false } = {}) {
  expect(headers.get("x-content-type-options")).toBe("nosniff");
  expect(headers.get("x-frame-options")).toBe("DENY");
  expect(headers.get("referrer-policy")).toBe("no-referrer");
  expect(headers.get("cross-origin-opener-policy")).toBe("same-origin");
  expect(headers.get("cross-origin-resource-policy")).toBe(crossOrigin ? "cross-origin" : "same-origin");
  expect(headers.get("access-control-allow-origin")).toBe(crossOrigin ? "*" : null);
  if (indexable) expect(headers.get("x-robots-tag")).toBeNull();
  else expect(headers.get("x-robots-tag")).toContain("noindex");
  expect(headers.get("permissions-policy")).toContain("camera=()");
  expect(headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
}

describe("security headers", () => {
  it("hardens every API response", async () => {
    const res = await call("secret/meta", { id: "x", metaToken: "y" });
    expectHardened(res.headers);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(res.headers.get("strict-transport-security")).toContain("max-age=63072000");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("turns unexpected failures into a hardened, generic 500", async () => {
    const broken = { ...env, ASSETS: { fetch: () => Promise.reject(new Error("assets down")) } } as unknown as Env;
    const res = await worker.fetch(
      new Request("https://keyburn.dev/") as Request<unknown, IncomingRequestCfProperties>,
      broken,
      createExecutionContext(),
    );
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ success: false, error: "internal" });
    expectHardened(res.headers);
  });

  it("redirects www.keyburn.dev to keyburn.dev, keeping the path", async () => {
    const res = await fetchPage("https://www.keyburn.dev/s?x=1", { redirect: "manual" });
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("https://keyburn.dev/s?x=1");
  });

  it("sends visits to the first hosts to keyburn.dev, but keeps their API and CLI files", async () => {
    for (const host of ["secret.nafran.com", "secrets.nafran.com"]) {
      for (const [from, to] of [
        [`https://${host}/s?x=1`, "https://keyburn.dev/s?x=1"],
        [`http://${host}/`, "https://keyburn.dev/"],
        [`https://${host}/robots.txt`, "https://keyburn.dev/robots.txt"],
      ]) {
        const res = await fetchPage(from as string, { redirect: "manual" });
        expect(res.status, from).toBe(301);
        expect(res.headers.get("location"), from).toBe(to);
      }
      const api = await fetchPage(`https://${host}/api/v1/secret/meta`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: "x", metaToken: "y" }),
      });
      expect(api.status).not.toBe(301);
      expect(api.headers.get("content-type")).toContain("application/json");
      await api.arrayBuffer();
    }
  });

  it("redirects plain HTTP to HTTPS, keeping the path", async () => {
    const res = await fetchPage("http://keyburn.dev/s", { redirect: "manual" });
    expect(res.status).toBe(301);
    expect(res.headers.get("location")).toBe("https://keyburn.dev/s");
  });

  it("drops HSTS and insecure-request upgrades on localhost for development", async () => {
    const res = await fetchPage("http://localhost:8787/api/v1/nope", { method: "POST" });
    expect(res.headers.get("strict-transport-security")).toBeNull();
    expect(res.headers.get("content-security-policy")).not.toContain("upgrade-insecure-requests");
  });
});

describe.skipIf(!("ASSETS" in env))("pages", () => {
  it("serves pages with a strict CSP and Trusted Types", async () => {
    for (const path of ["/", "/s", "/m", "/request", "/r", "/i", "/security", "/agents"]) {
      const res = await fetchPage(`https://keyburn.dev${path}`, { headers: { accept: "text/html,*/*;q=0.8" } });
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
      const csp = res.headers.get("content-security-policy") ?? "";
      // Pinned to the app's own files: other same-origin paths (e.g. /cdn-cgi/) are not allowed.
      expect(csp).toContain("script-src https://keyburn.dev/assets/app.js;");
      expect(csp).toContain("connect-src https://keyburn.dev/api/v1/;");
      expect(csp).toContain("font-src https://keyburn.dev/assets/fonts/;");
      expect(csp).not.toContain("'self'");
      expect(csp).toContain("require-trusted-types-for 'script'");
      expect(csp).not.toContain("unsafe-inline");
      expect(csp).not.toContain("unsafe-eval");
      expect(res.headers.get("cache-control")).toBe("no-store, no-transform");
      const indexable = ["/", "/request", "/security", "/agents"].includes(path);
      expectHardened(res.headers, { indexable });
      // Agents can find the machine-readable descriptions from public pages.
      if (indexable) expect(res.headers.get("link")).toContain('</.well-known/api-catalog>; rel="api-catalog"');
      else expect(res.headers.get("link")).toBeNull();
      await res.arrayBuffer();
    }
  });

  it("serves Markdown versions to agents that ask for them", async () => {
    for (const path of ["/", "/request", "/security", "/agents", "/s", "/m", "/r", "/i"]) {
      const res = await fetchPage(`https://keyburn.dev${path}`, { headers: { accept: "text/markdown, text/html;q=0.9" } });
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/markdown; charset=utf-8");
      expect(res.headers.get("vary")).toBe("Accept");
      expect(Number(res.headers.get("x-markdown-tokens"))).toBeGreaterThan(50);
      expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
      const indexable = ["/", "/request", "/security", "/agents"].includes(path);
      expectHardened(res.headers, { indexable, crossOrigin: indexable });
      expect(await res.text()).toMatch(/^# /);
    }
    const html = await fetchPage("https://keyburn.dev/", { headers: { accept: "text/html" } });
    expect(html.headers.get("vary")).toContain("Accept");
    expect(html.headers.get("content-type")).toContain("text/html");
    await html.arrayBuffer();
  });

  it("tells agents and scripts how to open a link when they don't ask for HTML", async () => {
    // curl, scripts and agent fetch tools never send the key after "#", and rarely ask for HTML.
    const clients: (string | null)[] = [null, "*/*", "application/json, */*;q=0.5", "text/plain"];
    for (const path of ["/s", "/m", "/r", "/i"]) {
      for (const accept of clients) {
        const res = await fetchPage(`https://keyburn.dev${path}`, accept === null ? {} : { headers: { accept } });
        expect(res.status, `${path} ${accept}`).toBe(200);
        expect(res.headers.get("content-type"), `${path} ${accept}`).toBe("text/markdown; charset=utf-8");
        expect(res.headers.get("vary")).toBe("Accept");
        expectHardened(res.headers);
        expect(await res.text()).toMatch(/^# KeyBurn (secret|receipt|request|inbox) link\n/);
      }
      // Browsers always ask for HTML, so people still get the page.
      for (const accept of ["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/xhtml+xml"]) {
        const res = await fetchPage(`https://keyburn.dev${path}`, { headers: { accept } });
        expect(res.headers.get("content-type"), `${path} ${accept}`).toContain("text/html");
        expect(res.headers.get("vary")).toContain("Accept");
        await res.arrayBuffer();
      }
    }
    // Public pages stay HTML for clients like link previewers.
    for (const accept of [null, "*/*"]) {
      const res = await fetchPage("https://keyburn.dev/", accept === null ? {} : { headers: { accept } });
      expect(res.headers.get("content-type")).toContain("text/html");
      await res.arrayBuffer();
    }
    const head = await fetchPage("https://keyburn.dev/s", { method: "HEAD", headers: { accept: "*/*" } });
    expect(head.headers.get("content-type")).toBe("text/markdown; charset=utf-8");
    expect(await head.text()).toBe("");
  });

  it("gives agents a working, pinned way to open a secret link", async () => {
    const markdown = await (await fetchPage("https://keyburn.dev/s", { headers: { accept: "*/*" } })).text();
    const html = await (await fetchPage("https://keyburn.dev/s", { headers: { accept: "text/html" } })).text();
    for (const text of [markdown, html]) {
      expect(text).toMatch(/https:\/\/keyburn\.dev\/cli\/osss-\d+\.\d+\.\d+\.mjs/);
      expect(text).toMatch(/[0-9a-f]{64} {2}osss\.download" \| shasum -a 256 -c/);
      expect(text).toContain("| node ~/.osss/osss.mjs open -");
    }
    expect(markdown).toContain("node ~/.osss/osss.mjs run <handle> -- <command>");
    expect(html).toContain("node ~/.osss/osss.mjs run &lt;handle&gt; -- &lt;command&gt;");
    // Agents are told to install osss and open the link, not to stop and wait.
    expect(markdown).not.toMatch(/approval/i);
  });

  it("serves the discovery documents for crawlers and agents", async () => {
    const docs: [string, string, boolean][] = [
      ["/robots.txt", "text/plain; charset=utf-8", false],
      ["/sitemap.xml", "application/xml; charset=utf-8", false],
      ["/llms.txt", "text/markdown; charset=utf-8", true],
      ["/auth.md", "text/markdown; charset=utf-8", true],
      ["/index.md", "text/markdown; charset=utf-8", true],
      ["/agents.md", "text/markdown; charset=utf-8", true],
      ["/openapi.json", "application/json; charset=utf-8", true],
      ["/.well-known/api-catalog", 'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"', true],
      ["/.well-known/ai-catalog.json", "application/json; charset=utf-8", true],
      ["/.well-known/agent-skills/index.json", "application/json; charset=utf-8", true],
      ["/.well-known/agent-skills/osss/SKILL.md", "text/markdown; charset=utf-8", true],
    ];
    for (const [path, type, crossOrigin] of docs) {
      const res = await fetchPage(`https://keyburn.dev${path}`);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type"), path).toBe(type);
      expectHardened(res.headers, { indexable: true, crossOrigin });
      await res.arrayBuffer();
    }
    const robots = await (await fetchPage("https://keyburn.dev/robots.txt")).text();
    expect(robots).toMatch(/^Content-Signal: search=yes, ai-input=yes, ai-train=no$/m);
    expect(robots).toMatch(/^Sitemap: https:\/\/keyburn\.dev\/sitemap\.xml$/m);
    expect(robots).toMatch(/^Disallow: \/$/m);
    for (const path of ["/s", "/m", "/r", "/i"]) expect(robots).toContain(`\nAllow: ${path}$\n`);
    const catalog = await (await fetchPage("https://keyburn.dev/.well-known/api-catalog")).json<{ linkset: Record<string, unknown>[] }>();
    expect(Object.keys(catalog.linkset[0]!)).toEqual(["anchor", "service-desc", "service-doc", "status"]);
    const ard = await (await fetchPage("https://keyburn.dev/.well-known/ai-catalog.json")).json<{ entries: Record<string, unknown>[] }>();
    for (const entry of ard.entries) {
      expect(entry.identifier).toMatch(/^urn:air:keyburn\.dev:/);
      expect("url" in entry !== "data" in entry).toBe(true);
    }
    const index = await (await fetchPage("https://keyburn.dev/.well-known/agent-skills/index.json")).json<{
      skills: { url: string; digest: string }[];
    }>();
    const skill = await fetchPage(`https://keyburn.dev${new URL(index.skills[0]!.url).pathname}`);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await skill.arrayBuffer()));
    expect(index.skills[0]!.digest).toBe(`sha256:${[...digest].map((b) => b.toString(16).padStart(2, "0")).join("")}`);
  });

  it("answers the health check without touching storage", async () => {
    const res = await call("health", null, { method: "GET" });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, data: { status: "ok", protocol: "osss/v1" } });
  });

  it("serves the bundle with revalidation and no-transform", async () => {
    const res = await fetchPage("https://keyburn.dev/assets/app.js");
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-cache, no-transform");
    expectHardened(res.headers);
    await res.arrayBuffer();
  });

  it("serves the logo images with their types", async () => {
    for (const [path, type] of [
      ["/assets/brand/keyburn-mark-animated.webp", "image/webp"],
      ["/assets/brand/keyburn-mark.webp", "image/webp"],
      ["/assets/brand/favicon-32.png", "image/png"],
      ["/assets/brand/apple-touch-icon.png", "image/png"],
      ["/assets/brand/fire.mp4", "video/mp4"],
      ["/assets/brand/fire.webm", "video/webm"],
      ["/assets/brand/burn-mask.svg", "image/svg+xml"],
    ]) {
      const res = await fetchPage(`https://keyburn.dev${path}`);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type"), path).toBe(type);
      expectHardened(res.headers);
      await res.arrayBuffer();
    }
    const range = await fetchPage("https://keyburn.dev/assets/brand/fire.mp4", { headers: { range: "bytes=0-99" } });
    expect(range.status).toBe(206);
    expect(range.headers.get("content-range")).toMatch(/^bytes 0-99\//);
    expect((await range.arrayBuffer()).byteLength).toBe(100);
    const tail = await fetchPage("https://keyburn.dev/assets/brand/fire.mp4", { headers: { range: "bytes=-10" } });
    expect(tail.status).toBe(206);
    expect((await tail.arrayBuffer()).byteLength).toBe(10);
    const beyond = await fetchPage("https://keyburn.dev/assets/brand/fire.mp4", { headers: { range: "bytes=99999999-" } });
    expect(beyond.status).toBe(416);
    await beyond.arrayBuffer();
    const page = await fetchPage("https://keyburn.dev/");
    expect(page.headers.get("content-security-policy")).toContain("media-src https://keyburn.dev/assets/brand/;");
    expect(page.headers.get("content-security-policy")).toContain("img-src https://keyburn.dev/assets/logo.svg https://keyburn.dev/favicon.svg https://keyburn.dev/assets/brand/;");
    await page.arrayBuffer();
  });

  it("serves the self-hosted fonts as woff2", async () => {
    const res = await fetchPage("https://keyburn.dev/assets/fonts/poppins-400-latin.woff2");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("font/woff2");
    expectHardened(res.headers);
    expect(new Uint8Array(await res.arrayBuffer()).slice(0, 4)).toEqual(new TextEncoder().encode("wOF2"));
  });

  it("serves the agent tool as plain text that browsers won't run", async () => {
    const sumsFile = await fetchPage("https://keyburn.dev/cli/SHA256SUMS");
    const [, release] = (await sumsFile.text()).trim().split(/\s+/);
    for (const path of [`/cli/${release}`, "/cli/SHA256SUMS"]) {
      const res = await fetchPage(`https://keyburn.dev${path}`);
      expect(res.status, path).toBe(200);
      expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      expect(res.headers.get("cache-control")).toBe("no-cache, no-transform");
      expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
      expectHardened(res.headers);
      await res.arrayBuffer();
    }
    const sums = await (await fetchPage("https://keyburn.dev/cli/SHA256SUMS")).text();
    const [hash, name] = sums.trim().split(/\s+/);
    const versioned = await fetchPage(`https://keyburn.dev/cli/${name}`);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await versioned.arrayBuffer()));
    expect([...digest].map((b) => b.toString(16).padStart(2, "0")).join("")).toBe(hash);
  });

  it("returns a hardened 404 for unknown paths and traversal attempts", async () => {
    for (const path of [
      "/nope",
      "/s.html",
      "/assets/%2e%2e/wrangler.jsonc",
      "/index.html",
      "/s/",
      "/agents.html",
      "/cli/",
      "/cli/osss.mjs",
      "/cli/osss-9.9.9.mjs",
      "/cli/osss-1.0.0.mjs.map",
      "/cli/%2e%2e/index.html",
      "/cli/../src/cli/main.ts",
      "/md/index.md",
      "/assets/fonts/OFL-Poppins.txt",
      "/assets/fonts/missing.woff2",
      "/assets/fonts/%2e%2e/%2e%2e/wrangler.jsonc",
      "/assets/fonts/poppins-400-latin.woff2.map",
      "/assets/brand/missing.webp",
      "/assets/brand/keyburn-mark.svg",
      "/s.md",
      "/m.md",
      "/.well-known/api-catalog.json",
      "/.well-known/",
      "/.well-known/agent-skills/osss/",
    ]) {
      const res = await fetchPage(`https://keyburn.dev${path}`);
      expect(res.status, path).toBe(404);
      expectHardened(res.headers);
      await res.arrayBuffer();
    }
  });

  it("only allows GET and HEAD for pages", async () => {
    const res = await fetchPage("https://keyburn.dev/", { method: "POST" });
    expect(res.status).toBe(405);
    await res.arrayBuffer();
  });
});
