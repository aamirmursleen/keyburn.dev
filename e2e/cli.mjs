// End-to-end test of the agent tool (the built public/cli/osss-<version>.mjs) against
// `wrangler dev`: the CLI, MCP server and Claude Code hook open links made in the browser and
// vice versa, values never appear in tool output, local copies are encrypted, refusals behave as
// documented, and a browser agent can create links through WebMCP.
//
// Usage: npm run build && node e2e/cli.mjs   (uses port E2E_PORT + 1, default 8800)

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { chromium } from "playwright";
import { startServer, stopServer } from "./server.mjs";

const PORT = Number(process.env.E2E_PORT ?? 8799) + 1;
const BASE = `http://localhost:${PORT}`;
const VERSION = /VERSION = "([\d.]+)"/.exec(await readFile(new URL("../src/cli/version.ts", import.meta.url), "utf8"))[1];
const CLI = new URL(`../public/cli/osss-${VERSION}.mjs`, import.meta.url).pathname;
const HOME = await mkdtemp(join(tmpdir(), "osss-e2e-"));
const ENV = { ...process.env, OSSS_ORIGIN: BASE, OSSS_HOME: HOME, NODE_OPTIONS: "" };

/**
 * Runs the CLI without a controlling terminal (detached), like an agent's shell tool does,
 * so anything that needs a person at a terminal must refuse instead of waiting.
 */
function osss(args, { input = "", env = ENV } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (c) => (stdout += c));
    child.stderr.setEncoding("utf8").on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(input);
  });
}

async function json(args, options) {
  const result = await osss([...args, "--json"], options);
  assert.equal(result.code, 0, `osss ${args[0]} failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

function mcpClient() {
  const child = spawn(process.execPath, [CLI, "mcp"], { env: ENV, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  const waiting = new Map();
  const transcript = [];
  createInterface({ input: child.stdout }).on("line", (line) => {
    transcript.push(line);
    const message = JSON.parse(line);
    waiting.get(message.id)?.(message);
    waiting.delete(message.id);
  });
  let next = 1;
  return {
    transcript,
    request(method, params) {
      const id = next++;
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      return new Promise((resolve) => waiting.set(id, resolve));
    },
    notify(method) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method })}\n`);
    },
    async close() {
      child.stdin.end();
      await new Promise((resolve) => child.on("close", resolve));
    },
  };
}

async function vaultHasNo(value) {
  const dir = join(HOME, "vault");
  for (const name of await readdir(dir)) {
    const bytes = await readFile(join(dir, name));
    assert.equal(bytes.includes(Buffer.from(value)), false, `plaintext found in ${name}`);
  }
}

async function run(browser) {
  // ---- 1. The download is what SHA256SUMS says ---------------------------------
  const sums = await (await fetch(`${BASE}/cli/SHA256SUMS`)).text();
  const [hash, name] = sums.trim().split(/\s+/);
  const served = Buffer.from(await (await fetch(`${BASE}/cli/${name}`)).arrayBuffer());
  assert.equal(createHash("sha256").update(served).digest("hex"), hash);
  assert.deepEqual(served, await readFile(CLI));
  assert.equal((await fetch(`${BASE}/cli/osss.mjs`)).status, 404, "no unversioned download");

  // ---- 2. CLI send -> CLI open -> run ------------------------------------------
  const value = "s3cr3t-api-key-0123456789";
  const shared = await json(["send", "--views", "1", "--expires", "1h"], {
    input: `API_KEY=${value}\nREGION=eu-west-1\nNODE_OPTIONS=--require=/tmp/evil.js\n`,
  });
  assert.match(shared.link, new RegExp(`^${BASE}/s#[A-Za-z0-9_-]{43}$`));
  assert.equal(shared.passphrase, null);

  const opened = await json(["open", shared.link]);
  assert.match(opened.handle, /^osss_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(opened.variables, ["API_KEY", "REGION"]);
  assert.deepEqual(opened.refusedVariables, ["NODE_OPTIONS"]);
  assert.equal(opened.viewsLeft, 0);
  assert.equal(JSON.stringify(opened).includes(value), false, "open must never print the value");
  await vaultHasNo(value);

  const echoed = await osss(["run", opened.handle, "--", process.execPath, "-e", "console.log(process.env.API_KEY)"]);
  assert.equal(echoed.code, 0, echoed.stderr);
  assert.equal(echoed.stdout, "[redacted]\n");
  const checked = await osss([
    "run",
    opened.handle,
    "--",
    process.execPath,
    "-e",
    `console.log(process.env.API_KEY === ${JSON.stringify(value)}, process.env.REGION, process.env.NODE_OPTIONS === undefined || process.env.NODE_OPTIONS === "")`,
  ]);
  assert.equal(checked.stdout, "true [redacted] true\n");
  const only = await osss(["run", opened.handle, "--only", "REGION", "--", process.execPath, "-e", "console.log(typeof process.env.API_KEY)"]);
  assert.equal(only.stdout, "undefined\n");

  const again = await osss(["open", shared.link]);
  assert.equal(again.code, 3);
  assert.match(again.stderr, /no longer available/);
  const status = await json(["status", shared.receipt]);
  assert.equal(status.state, "viewed");
  assert.equal(status.views.length, 1);

  const revealed = await osss(["reveal", opened.handle]);
  assert.equal(revealed.code, 7, "reveal must refuse without a terminal");
  assert.equal(revealed.stdout.includes(value), false);
  assert.deepEqual((await json(["list"])).map((i) => i.id), [opened.handle.slice(5, 21)]);
  assert.deepEqual(await json(["forget", opened.handle]), { forgotten: 1 });
  assert.equal((await osss(["run", opened.handle, "--", process.execPath, "-e", ""])).code, 3);

  // ---- 3. Attached files arrive intact as OSSS_SECRET_FILE and are removed afterwards ---
  const attachment = join(HOME, "service-account.json");
  const attachmentBytes = Buffer.from(Array.from({ length: 200_000 }, (_, i) => (i * 131) % 256));
  await writeFile(attachment, attachmentBytes);
  const withFile = await json(["send", "--attach", attachment], { input: "" });
  await rm(attachment);
  const fileOpened = await json(["open", withFile.link]);
  assert.equal(fileOpened.hasFile, true);
  const fileHash = await osss([
    "run",
    fileOpened.handle,
    "--",
    process.execPath,
    "-e",
    "const fs=require('fs');const p=process.env.OSSS_SECRET_FILE;console.log(require('crypto').createHash('sha256').update(fs.readFileSync(p)).digest('hex'));console.log(p)",
  ]);
  const [digest, tempPath] = fileHash.stdout.trim().split("\n");
  assert.equal(digest, createHash("sha256").update(attachmentBytes).digest("hex"));
  await assert.rejects(readFile(tempPath), "the temporary file must be removed");

  // ---- 4. Passphrases are only ever typed at a terminal ---------------------------
  const locked = await json(["send", "--passphrase"], { input: "behind a passphrase" });
  assert.match(locked.passphrase, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
  const needs = await osss(["open", locked.link]);
  assert.equal(needs.code, 7);
  assert.match(needs.stderr, /interactive terminal/);

  // ---- 5. Refusals -------------------------------------------------------------
  const evil = await osss(["open", shared.link], { env: { ...ENV, OSSS_ORIGIN: "https://evil.example" } });
  assert.equal(evil.code, 2);
  const foreign = await osss(["open", `https://secret.example/s#${"A".repeat(43)}`]);
  assert.equal(foreign.code, 2);
  assert.match(foreign.stderr, /Only links from/);

  // ---- 6. MCP: open, list, forget; passphrase secrets are refused -------------------
  const mcpValue = "mcp-only-secret-value-42";
  const forMcp = await json(["send"], { input: `DEPLOY_TOKEN=${mcpValue}` });
  const mcp = mcpClient();
  const init = await mcp.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
  assert.equal(init.result.protocolVersion, "2025-06-18");
  assert.match(init.result.instructions, /Never print/);
  mcp.notify("notifications/initialized");
  const tools = await mcp.request("tools/list", {});
  assert.deepEqual(tools.result.tools.map((t) => t.name), ["open_secret", "list_secrets", "forget_secret"]);
  const viaMcp = await mcp.request("tools/call", { name: "open_secret", arguments: { link: forMcp.link } });
  assert.equal(viaMcp.result.isError, undefined, JSON.stringify(viaMcp));
  const summary = viaMcp.result.structuredContent;
  assert.deepEqual(summary.variables, ["DEPLOY_TOKEN"]);
  assert.match(summary.runCommand, / run osss_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43} -- /);
  // Asking again in the same session never uses another view.
  const again2 = await mcp.request("tools/call", { name: "open_secret", arguments: { link: `<${forMcp.link}>.` } });
  assert.equal(again2.result.structuredContent.handle, summary.handle);
  const usedByAgent = await osss(["run", summary.handle, "--", process.execPath, "-e", "console.log(process.env.DEPLOY_TOKEN.length)"]);
  assert.equal(usedByAgent.stdout, `${mcpValue.length}\n`);
  const lockedViaMcp = await mcp.request("tools/call", { name: "open_secret", arguments: { link: locked.link } });
  assert.equal(lockedViaMcp.result.isError, true);
  assert.match(lockedViaMcp.result.content[0].text, /passphrase_required/);
  const listed = await mcp.request("tools/call", { name: "list_secrets", arguments: {} });
  assert.ok(listed.result.structuredContent.items.some((i) => summary.handle.includes(i.id)));
  const forgot = await mcp.request("tools/call", { name: "forget_secret", arguments: { target: summary.handle } });
  assert.deepEqual(forgot.result.structuredContent, { forgotten: 1 });
  const afterForget = await mcp.request("tools/call", { name: "open_secret", arguments: { link: forMcp.link } });
  assert.equal(afterForget.result.isError, true);
  assert.match(afterForget.result.content[0].text, /already opened in this session/);
  await mcp.close();
  assert.equal(mcp.transcript.join("\n").includes(mcpValue), false, "the MCP transcript must never contain the value");

  // ---- 7. Claude Code hook: links in a prompt are opened here and never sent -------------
  const forHook = await json(["send"], { input: "HOOK_TOKEN=hook-protected-value-99" });
  const key = forHook.link.split("#")[1];
  const blocked = await osss(["hook", "claude-code"], {
    input: JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt: `Deploy with ${forHook.link}, thanks` }),
  });
  assert.equal(blocked.code, 0, blocked.stderr);
  const decision = JSON.parse(blocked.stdout);
  assert.equal(decision.decision, "block");
  assert.equal(decision.hookSpecificOutput.suppressOriginalPrompt, true);
  assert.equal(blocked.stdout.includes(key), false, "the hook must not echo the link");
  const hookHandle = /osss_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43}/.exec(decision.reason)[0];
  assert.match(decision.reason, /Deploy with osss_[A-Za-z0-9_-]{16}_[A-Za-z0-9_-]{43} \(osss handle; variables: HOOK_TOKEN\), thanks/);
  const viaHook = await osss(["run", hookHandle, "--", process.execPath, "-e", "console.log(process.env.HOOK_TOKEN.length)"]);
  assert.equal(viaHook.stdout, "23\n");
  const passThrough = await osss(["hook", "claude-code"], { input: JSON.stringify({ prompt: "no links here, see https://keyburn.dev/agents" }) });
  assert.deepEqual([passThrough.code, passThrough.stdout], [0, ""], "prompts without links pass with no output");

  // ---- 8. WebMCP: a browser agent creates a link with the page's own encryption ---------
  const agentContext = await browser.newContext();
  await agentContext.addInitScript(() => {
    const tools = [];
    Object.defineProperty(document, "modelContext", { value: { registerTool: (tool) => (tools.push(tool), Promise.resolve()) } });
    window.__webmcpTools = tools;
  });
  const agentPage = await agentContext.newPage();
  await agentPage.goto(`${BASE}/`);
  await agentPage.waitForFunction(() => window.__webmcpTools.length === 1);
  const made = await agentPage.evaluate(async () => {
    const tool = window.__webmcpTools[0];
    const ok = await tool.execute({ text: "WEBMCP_TOKEN=made-by-a-browser-agent", views: 1, expiresIn: "1h" });
    const bad = await tool.execute({ text: "", views: 4 });
    return { name: tool.name, ok, bad };
  });
  assert.equal(made.name, "create_secret_link");
  assert.equal(made.bad.isError, true);
  const createdByAgent = JSON.parse(made.ok.content[0].text);
  assert.match(createdByAgent.link, new RegExp(`^${BASE}/s#[A-Za-z0-9_-]{43}$`));
  await agentPage.waitForSelector("#created:not([hidden])");
  assert.equal(await agentPage.inputValue("#secret-link"), createdByAgent.link);
  const fromAgent = await json(["open", createdByAgent.link]);
  assert.deepEqual(fromAgent.variables, ["WEBMCP_TOKEN"]);

  // ---- 9. Browser -> CLI and CLI -> browser ---------------------------------------
  const page = await (await browser.newContext()).newPage();
  await page.goto(`${BASE}/`);
  await page.fill("#secret", "MADE_IN_PAGE=browser-made-value-77");
  await page.click("#create-btn");
  await page.waitForSelector("#created:not([hidden])");
  const browserLink = await page.inputValue("#secret-link");
  const fromBrowser = await json(["open", browserLink]);
  assert.deepEqual(fromBrowser.variables, ["MADE_IN_PAGE"]);
  const read = await osss(["run", fromBrowser.handle, "--", process.execPath, "-e", "console.log(process.env.MADE_IN_PAGE.endsWith('-77'))"]);
  assert.equal(read.stdout, "true\n");

  const forBrowser = await json(["send"], { input: "made by the cli 🐑" });
  const reader = await (await browser.newContext()).newPage();
  await reader.goto(forBrowser.link);
  await reader.waitForSelector("#v-ready:not([hidden])");
  await reader.click("#v-reveal");
  await reader.waitForSelector("#v-revealed:not([hidden])");
  assert.equal(await reader.textContent("#v-text"), "made by the cli 🐑");
}

const server = await startServer(PORT);
const browser = await chromium.launch();
try {
  await run(browser);
  console.log("CLI E2E passed: CLI and MCP open browser links and vice versa, values never printed, local copies encrypted.");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await browser.close();
  stopServer(server);
  await rm(HOME, { recursive: true, force: true });
}
