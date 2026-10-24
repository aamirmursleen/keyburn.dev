import { describe, expect, it } from "vitest";
import { Api, type Fetch } from "../../src/cli/http";

function fake(respond: (url: string, init: RequestInit) => Response | Promise<Response>): { fetch: Fetch; calls: { url: string; init: RequestInit }[] } {
  const calls: { url: string; init: RequestInit }[] = [];
  return {
    calls,
    fetch: async (url, init) => {
      calls.push({ url, init });
      return respond(url, init);
    },
  };
}

const ok = (data: unknown, status = 200) => Response.json({ success: true, data }, { status });

describe("Api.post", () => {
  it("posts JSON to the API path and never follows redirects", async () => {
    const f = fake(() => ok({ a: 1 }));
    const api = new Api("https://secret.nafran.com", f.fetch);
    expect(await api.post("secret/meta", { id: "x" })).toEqual({ ok: true, data: { a: 1 } });
    expect(f.calls[0]!.url).toBe("https://secret.nafran.com/api/v1/secret/meta");
    expect(f.calls[0]!.init.redirect).toBe("error");
    expect(f.calls[0]!.init.method).toBe("POST");
    expect(f.calls[0]!.init.body).toBe('{"id":"x"}');
    expect(f.calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  it("maps only known error codes and keeps attemptsLeft", async () => {
    const api = (r: Response) => new Api("https://secret.nafran.com", fake(() => r).fetch);
    expect(await api(Response.json({ success: false, error: "not_found" }, { status: 404 })).post("x", {})).toEqual({
      ok: false,
      status: 404,
      error: "not_found",
    });
    expect(await api(Response.json({ success: false, error: "wrong_passphrase", attemptsLeft: 3 }, { status: 403 })).post("x", {})).toEqual({
      ok: false,
      status: 403,
      error: "wrong_passphrase",
      attemptsLeft: 3,
    });
    expect(await api(Response.json({ success: false, error: "<script>" }, { status: 400 })).post("x", {})).toMatchObject({ error: "internal" });
    expect(await api(new Response("not json", { status: 200 })).post("x", {})).toMatchObject({ ok: false, error: "internal" });
    expect(await api(Response.json({ success: true }, { status: 200 })).post("x", {})).toMatchObject({ ok: false });
    expect(await api(ok({ a: 1 }, 500)).post("x", {})).toMatchObject({ ok: false, status: 500 });
  });

  it("refuses oversized responses", async () => {
    const huge = JSON.stringify({ success: true, data: "x".repeat(1024 * 1024) });
    const api = new Api("https://secret.nafran.com", fake(() => new Response(huge)).fetch);
    expect(await api.post("x", {})).toMatchObject({ ok: false, error: "internal" });
  });

  it("reports network failures, including redirects", async () => {
    const api = new Api("https://secret.nafran.com", async () => Promise.reject(new TypeError("fetch failed")));
    expect(await api.post("x", {})).toEqual({ ok: false, status: 0, error: "network" });
    expect(await api.upload("secret", "id", "t", new Uint8Array(1))).toEqual({ ok: false, status: 0, error: "network" });
    expect(await api.download("secret", "id", "t", 1)).toEqual({ ok: false, status: 0, error: "network" });
  });
});

describe("Api.upload", () => {
  it("sends the ciphertext with the upload token", async () => {
    const f = fake(() => ok({ size: 3 }));
    const api = new Api("https://secret.nafran.com", f.fetch);
    expect(await api.upload("secret", "ID", "TOKEN", new Uint8Array([1, 2, 3]))).toEqual({ ok: true, data: { size: 3 } });
    const { init, url } = f.calls[0]!;
    expect(url).toBe("https://secret.nafran.com/api/v1/upload");
    expect(init.method).toBe("PUT");
    expect(init.redirect).toBe("error");
    expect((init.headers as Record<string, string>)["x-vault-box"]).toBe("secret:ID");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer TOKEN");
  });

  it("maps upload errors", async () => {
    const api = new Api("https://secret.nafran.com", fake(() => Response.json({ success: false, error: "payload_too_large" }, { status: 413 })).fetch);
    expect(await api.upload("secret", "ID", "T", new Uint8Array(1))).toMatchObject({ ok: false, error: "payload_too_large" });
  });
});

describe("Api.download", () => {
  it("accepts exactly the expected number of bytes", async () => {
    const bytes = new Uint8Array([9, 8, 7, 6]);
    const exact = new Api("https://secret.nafran.com", fake(() => new Response(bytes)).fetch);
    expect(await exact.download("secret", "ID", "T", 4)).toEqual({ ok: true, data: bytes });
    expect(await exact.download("secret", "ID", "T", 3)).toMatchObject({ ok: false, error: "network" });
    expect(await exact.download("secret", "ID", "T", 5)).toMatchObject({ ok: false, error: "network" });
  });

  it("maps download errors", async () => {
    const api = new Api("https://secret.nafran.com", fake(() => Response.json({ success: false, error: "forbidden" }, { status: 403 })).fetch);
    expect(await api.download("secret", "ID", "T", 4)).toEqual({ ok: false, status: 403, error: "forbidden" });
  });
});
