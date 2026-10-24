import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import { brotliCompressSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { plainFetch } from "../../src/cli/transport";

let server: Server;
let base: string;
const seen: { method: string; url: string; headers: IncomingHttpHeaders; body: Buffer }[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks) });
      if (req.url === "/json") {
        res.writeHead(200, { "content-type": "application/json" }).end('{"success":true,"data":1}');
      } else if (req.url === "/brotli") {
        // Even when the client said identity, a hostile server may compress anyway.
        res.writeHead(200, { "content-type": "application/json", "content-encoding": "br" }).end(brotliCompressSync('{"success":true}'));
      } else if (req.url === "/gzip-upper") {
        res.writeHead(200, { "content-encoding": " GZIP " }).end("x");
      } else if (req.url === "/redirect") {
        res.writeHead(302, { location: "https://evil.example/" }).end();
      } else if (req.url === "/slow") {
        setTimeout(() => res.writeHead(200).end("late"), 2000);
      } else if (req.url === "/empty") {
        res.writeHead(204).end();
      } else {
        res.writeHead(404, { "content-type": "application/json" }).end('{"success":false,"error":"not_found"}');
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  base = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

describe("plainFetch", () => {
  it("sends JSON with an explicit length, asks for no compression and returns the body", async () => {
    const res = await plainFetch(`${base}/json`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ a: "é" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ success: true, data: 1 });
    const req = seen.at(-1)!;
    expect(req.headers["accept-encoding"]).toBe("identity");
    expect(req.headers["content-length"]).toBe(String(Buffer.byteLength('{"a":"é"}')));
    expect(req.headers.connection).toBe("close");
    expect(req.body.toString()).toBe('{"a":"é"}');
  });

  it("uploads bytes with their length", async () => {
    await plainFetch(`${base}/json`, { method: "PUT", headers: { "content-type": "application/octet-stream" }, body: new Uint8Array([1, 2, 3]) });
    expect(seen.at(-1)!.headers["content-length"]).toBe("3");
    expect([...seen.at(-1)!.body]).toEqual([1, 2, 3]);
  });

  it("refuses compressed responses without decompressing them", async () => {
    await expect(plainFetch(`${base}/brotli`, { method: "POST", body: "{}" })).rejects.toThrow(/Compressed response refused/);
    await expect(plainFetch(`${base}/gzip-upper`, { method: "GET" })).rejects.toThrow(/Compressed response refused/);
  });

  it("refuses redirects", async () => {
    await expect(plainFetch(`${base}/redirect`, { method: "GET" })).rejects.toThrow(/Redirect refused/);
  });

  it("passes error statuses and empty responses through", async () => {
    const missing = await plainFetch(`${base}/nope`, { method: "GET" });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ success: false, error: "not_found" });
    const empty = await plainFetch(`${base}/empty`, { method: "GET" });
    expect(empty.status).toBe(204);
    expect(empty.body).toBeNull();
  });

  it("honours the abort signal", async () => {
    await expect(plainFetch(`${base}/slow`, { method: "GET", signal: AbortSignal.timeout(100) })).rejects.toThrow();
  });

  it("refuses other protocols and bodies", async () => {
    await expect(plainFetch("ftp://127.0.0.1/", { method: "GET" })).rejects.toThrow(/Unsupported protocol/);
    await expect(plainFetch(`${base}/json`, { method: "POST", body: new Blob(["x"]) })).rejects.toThrow(/Unsupported request body/);
  });
});
