import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { CliError } from "../../src/cli/errors";
import { handleMessage, INSTRUCTIONS, serveMcp, SUPPORTED_PROTOCOLS, type McpDeps, type OpenSummary } from "../../src/cli/mcp";

const summary: OpenSummary = {
  handle: "osss_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  contains: "environment variables",
  variables: ["API_KEY"],
  refusedVariables: [],
  hasFile: false,
  viewsLeft: 0,
  localCopyExpiresAt: "2026-10-25T00:00:00.000Z",
  runCommand: "osss run osss_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB -- <command> [args...]",
};

function deps(overrides: Partial<McpDeps> = {}): McpDeps {
  return {
    open: vi.fn(async () => summary),
    list: vi.fn(async () => [{ id: "AAAAAAAAAAAAAAAA", expiresAt: "2026-10-25T00:00:00.000Z" }]),
    forget: vi.fn(async () => 1),
    ...overrides,
  };
}

const call = (d: McpDeps, name: string, args?: unknown) =>
  handleMessage(d, { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name, arguments: args } }) as Promise<{
    result: { isError?: boolean; content: { type: string; text: string }[]; structuredContent?: unknown };
  }>;

describe("handleMessage", () => {
  it("negotiates the protocol version and sends the safety instructions", async () => {
    const reply = (await handleMessage(deps(), {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } },
    })) as { result: { protocolVersion: string; instructions: string; capabilities: unknown; serverInfo: { name: string } } };
    expect(reply.result.protocolVersion).toBe("2025-06-18");
    expect(reply.result.instructions).toBe(INSTRUCTIONS);
    expect(reply.result.instructions).toMatch(/Never print/);
    expect(reply.result.capabilities).toEqual({ tools: { listChanged: false } });
    expect(reply.result.serverInfo.name).toBe("osss");

    const unknown = (await handleMessage(deps(), { jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } })) as {
      result: { protocolVersion: string };
    };
    expect(unknown.result.protocolVersion).toBe(SUPPORTED_PROTOCOLS[0]);
  });

  it("lists exactly three tools with strict schemas", async () => {
    const reply = (await handleMessage(deps(), { jsonrpc: "2.0", id: "x", method: "tools/list" })) as {
      id: string;
      result: { tools: { name: string; inputSchema: { additionalProperties: boolean } }[] };
    };
    expect(reply.id).toBe("x");
    expect(reply.result.tools.map((t) => t.name)).toEqual(["open_secret", "list_secrets", "forget_secret"]);
    for (const tool of reply.result.tools) expect(tool.inputSchema.additionalProperties).toBe(false);
  });

  it("answers ping, ignores notifications and rejects unknown methods", async () => {
    expect(await handleMessage(deps(), { jsonrpc: "2.0", id: 3, method: "ping" })).toEqual({ jsonrpc: "2.0", id: 3, result: {} });
    expect(await handleMessage(deps(), { jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
    expect(await handleMessage(deps(), { jsonrpc: "2.0", id: 4, method: "resources/list" })).toMatchObject({ error: { code: -32601 } });
    expect(await handleMessage(deps(), { jsonrpc: "1.0", id: 5, method: "ping" })).toMatchObject({ id: null, error: { code: -32600 } });
    expect(await handleMessage(deps(), "nonsense")).toMatchObject({ error: { code: -32600 } });
  });

  it("opens a link and returns the handle, never a value", async () => {
    const d = deps();
    const reply = await call(d, "open_secret", { link: "https://secret.nafran.com/s#abc" });
    expect(d.open).toHaveBeenCalledWith("https://secret.nafran.com/s#abc");
    expect(reply.result.isError).toBeUndefined();
    expect(reply.result.structuredContent).toEqual(summary);
    expect(JSON.parse(reply.result.content[0]!.text)).toEqual(summary);
  });

  it("validates arguments exactly", async () => {
    const d = deps();
    for (const args of [undefined, {}, { link: 5 }, { link: "x".repeat(513) }, { link: "a", extra: 1 }, ["a"]]) {
      const reply = await call(d, "open_secret", args);
      expect(reply.result.isError, JSON.stringify(args)).toBe(true);
    }
    expect(d.open).not.toHaveBeenCalled();
    expect((await call(d, "list_secrets", { any: 1 })).result.isError).toBe(true);
    expect((await call(d, "forget_secret", {})).result.isError).toBe(true);
    expect((await call(d, "forget_secret", { all: true })).result.isError).toBe(true);
    expect((await call(d, "forget_secret", { target: 3 })).result.isError).toBe(true);
    expect((await call(d, "forget_secret", { target: "" })).result.isError).toBe(true);
    expect((await call(d, "nope", {})).result.isError).toBe(true);
  });

  it("lists and forgets", async () => {
    const d = deps();
    expect(JSON.parse((await call(d, "list_secrets")).result.content[0]!.text)).toEqual({
      items: [{ id: "AAAAAAAAAAAAAAAA", expiresAt: "2026-10-25T00:00:00.000Z" }],
    });
    expect(JSON.parse((await call(d, "forget_secret", { target: "AAAAAAAAAAAAAAAA" })).result.content[0]!.text)).toEqual({ forgotten: 1 });
    expect(d.forget).toHaveBeenLastCalledWith("AAAAAAAAAAAAAAAA");
  });

  it("returns fixed error messages and never an unexpected error's text", async () => {
    const known = await call(deps({ open: async () => Promise.reject(new CliError("gone", "This secret is no longer available (viewed).")) }), "open_secret", {
      link: "x",
    });
    expect(known.result.isError).toBe(true);
    expect(JSON.parse(known.result.content[0]!.text)).toEqual({ error: "gone", message: "This secret is no longer available (viewed)." });

    const leaky = await call(deps({ open: async () => Promise.reject(new Error("value s3cr3t leaked in message")) }), "open_secret", { link: "x" });
    expect(leaky.result.content[0]!.text).not.toContain("s3cr3t");
    expect(JSON.parse(leaky.result.content[0]!.text)).toEqual({ error: "internal", message: "Unexpected error." });
  });
});

describe("serveMcp", () => {
  async function session(lines: string[], d: McpDeps = deps(), tail = ""): Promise<unknown[]> {
    const input = new PassThrough();
    const output = new PassThrough();
    let text = "";
    output.setEncoding("utf8");
    output.on("data", (chunk: string) => (text += chunk));
    const done = serveMcp(d, input, output);
    for (const line of lines) input.write(`${line}\n`);
    input.end(tail);
    await done;
    return text
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  }

  it("speaks newline-delimited JSON-RPC and nothing else", async () => {
    const replies = await session([
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25" } }),
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      "",
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    ]);
    expect(replies).toHaveLength(2);
    expect(replies[0]).toMatchObject({ id: 1, result: { protocolVersion: "2025-11-25" } });
    expect(replies[1]).toMatchObject({ id: 2 });
  });

  it("rejects malformed, batched and oversized messages", async () => {
    const replies = await session([
      "{not json",
      JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "ping" }]),
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping", params: { pad: "x".repeat(1024 * 1024) } }),
    ]);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Batches are not supported" } },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Message too large" } },
    ]);
  });

  it("answers other calls while a slow open is in progress", async () => {
    let release: () => void = () => undefined;
    const slow = deps({ open: () => new Promise<OpenSummary>((resolve) => (release = () => resolve(summary))) });
    const input = new PassThrough();
    const output = new PassThrough();
    const replies: { id: number }[] = [];
    output.setEncoding("utf8");
    output.on("data", (chunk: string) => {
      for (const line of chunk.trim().split("\n")) replies.push(JSON.parse(line));
      if (replies.length === 1) release();
    });
    const done = serveMcp(slow, input, output);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "open_secret", arguments: { link: "x" } } })}\n`);
    input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}\n`);
    input.end();
    await done;
    expect(replies.map((r) => r.id)).toEqual([2, 1]);
  });

  it("refuses requests beyond the concurrency limit", async () => {
    const never = deps({ open: () => new Promise<OpenSummary>(() => undefined) });
    const input = new PassThrough();
    const output = new PassThrough();
    let text = "";
    output.setEncoding("utf8");
    output.on("data", (chunk: string) => (text += chunk));
    void serveMcp(never, input, output);
    for (let id = 1; id <= 9; id++) {
      input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "open_secret", arguments: { link: "x" } } })}\n`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(JSON.parse(text.trim())).toEqual({ jsonrpc: "2.0", id: 9, error: { code: -32000, message: "Server busy" } });
    input.end();
  });

  it("caps a line before buffering it, even without a newline", async () => {
    const huge = "x".repeat(1024 * 1024 + 10);
    const replies = await session([JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })], deps(), huge);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Message too large" } },
    ]);
  });

  it("accepts CRLF line endings and a final line without a newline", async () => {
    const replies = await session([], deps(), `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })}\r\n${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}`);
    expect(replies).toEqual([
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 2, result: {} },
    ]);
  });
});
