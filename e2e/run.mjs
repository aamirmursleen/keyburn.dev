// End-to-end test in a real browser against `wrangler dev` (local Workers,
// Durable Objects, R2 and rate limiting). Besides walking every user flow, it
// proves the zero-knowledge claims: link keys, passphrases and private keys
// must never appear in any request the browser sends.
//
// Usage: npm run build && npm run e2e
//        E2E_BASE=https://secret.onesmartsheep.com npm run e2e   (smoke-test a live deployment)

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, rm } from "node:fs/promises";
import { chromium } from "playwright";

// E2E_PORT lets several runs (e.g. parallel work trees) share one machine.
const PORT = Number(process.env.E2E_PORT ?? 8799);
const LIVE = process.env.E2E_BASE?.replace(/\/$/, "");
const BASE = LIVE ?? `http://localhost:${PORT}`;
const ARTIFACTS = new URL("./artifacts/", import.meta.url);
const issues = [];
const outbound = [];
// The deliberate wrong-passphrase attempt returns 403; Chrome logs it as a failed load.
const EXPECTED = [/^\[reveal\] error: Failed to load resource: the server responded with a status of 403/];

function art(name) {
  return new URL(name, ARTIFACTS).pathname;
}

async function startServer() {
  await rm(`.wrangler/e2e-state-${PORT}`, { recursive: true, force: true });
  const child = spawn(
    "npx",
    ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--local-upstream", `localhost:${PORT}`, "--persist-to", `.wrangler/e2e-state-${PORT}`, "--show-interactive-dev-session=false"],
    // OSSS_DEV=1: a local server may run an agent tool build that isn't recorded as a release yet.
    { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, OSSS_DEV: "1" } },
  );
  let log = "";
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`wrangler dev did not start:\n${log}`)), 90_000);
    const onData = (chunk) => {
      log += chunk;
      if (log.includes("Ready on")) {
        clearTimeout(timer);
        resolve();
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => reject(new Error(`wrangler dev exited (${code}):\n${log}`)));
  });
  return child;
}

/** Records console problems and every request URL + body for leak checks. */
function watch(page, label) {
  page.on("console", (msg) => {
    if (msg.type() === "error" || msg.type() === "warning") issues.push(`[${label}] ${msg.type()}: ${msg.text()}`);
  });
  page.on("pageerror", (error) => issues.push(`[${label}] pageerror: ${error.message}`));
  page.on("request", (request) => {
    let body = "";
    try {
      body = request.postData() ?? "";
    } catch {
      body = "<binary>";
    }
    outbound.push({ label, url: request.url(), body });
  });
  return page;
}

async function newPage(browser, label, options = {}) {
  const context = await browser.newContext(options);
  return watch(await context.newPage(), label);
}

function assertNeverSent(value, what) {
  const leaks = outbound.filter((r) => r.url.includes(value) || r.body.includes(value));
  assert.equal(leaks.length, 0, `${what} was sent to the server: ${JSON.stringify(leaks.map((l) => l.url))}`);
}

const shown = (page, selector, timeout = 30_000) => page.waitForSelector(`${selector}:not([hidden])`, { timeout });

async function createSecret(page, { text, passphrase = false, file = null, views = "1" }) {
  await page.goto(`${BASE}/`);
  if (text) await page.fill("#secret", text);
  await page.selectOption("#views", views);
  if (file) await page.setInputFiles("#c-file", file);
  let pass = null;
  if (passphrase) {
    await page.click("#passphrase-generate");
    pass = await page.inputValue("#passphrase");
  }
  await page.click("#create-btn");
  await shown(page, "#created");
  return {
    link: await page.inputValue("#secret-link"),
    manage: await page.inputValue("#manage-link"),
    pass,
  };
}

async function run(browser) {
  // ---- 1. Text secret with passphrase ------------------------------------
  const sender = await newPage(browser, "create");
  const response = await sender.goto(`${BASE}/`);
  const csp = response.headers()["content-security-policy"];
  assert.match(csp, /require-trusted-types-for 'script'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);

  const text = "db-password: s3cr3t-🐑-value\nport: 5432";
  const a = await createSecret(sender, { text, passphrase: true });
  assert.match(a.link, /\/s#[A-Za-z0-9_-]{43}$/);
  assert.match(a.pass, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
  await sender.screenshot({ path: art("01-created.png"), fullPage: true });

  const key = a.link.split("#")[1];
  const recipient = await newPage(browser, "reveal");
  await recipient.goto(a.link);
  await shown(recipient, "#v-ready");
  assert.equal(new URL(recipient.url()).hash, "", "the key must be wiped from the address bar");
  await recipient.screenshot({ path: art("02-ready.png"), fullPage: true });

  await recipient.fill("#v-passphrase", "definitely-wrong");
  await recipient.click("#v-reveal");
  await shown(recipient, "#v-error");
  assert.match(await recipient.textContent("#v-error"), /4 attempts left/);

  await recipient.fill("#v-passphrase", a.pass);
  await recipient.click("#v-reveal");
  await shown(recipient, "#v-revealed");
  assert.equal(await recipient.textContent("#v-text"), text);
  await recipient.screenshot({ path: art("03-revealed.png"), fullPage: true });

  const again = await newPage(browser, "reveal-again");
  await again.goto(a.link);
  await shown(again, "#v-gone");
  assert.match(await again.textContent("#v-gone-title"), /already viewed/);

  const receipt = await newPage(browser, "manage");
  await receipt.goto(a.manage);
  await shown(receipt, "#m-view");
  assert.equal(await receipt.textContent("#m-badge"), "Opened");
  await receipt.screenshot({ path: art("04-receipt.png"), fullPage: true });

  assertNeverSent(key, "The secret link key");
  assertNeverSent(a.pass, "The passphrase");
  assertNeverSent("s3cr3t", "The plaintext");

  // ---- 2. File secret -----------------------------------------------------
  const fileBytes = Buffer.from(Array.from({ length: 300_000 }, (_, i) => (i * 7919) % 251));
  const b = await createSecret(sender, {
    text: "",
    file: { name: "client.env", mimeType: "text/plain", buffer: fileBytes },
  });
  const fileRecipient = await newPage(browser, "reveal-file");
  await fileRecipient.goto(b.link);
  await shown(fileRecipient, "#v-ready");
  await fileRecipient.click("#v-reveal");
  await shown(fileRecipient, "#v-revealed");
  assert.equal(await fileRecipient.isHidden("#v-text-block"), true, "file-only secret shows no text block");
  const [download] = await Promise.all([fileRecipient.waitForEvent("download"), fileRecipient.click("#v-download")]);
  assert.equal(download.suggestedFilename(), "client.env");
  assert.deepEqual(await readFile(await download.path()), fileBytes);
  await fileRecipient.screenshot({ path: art("05-file.png"), fullPage: true });
  assertNeverSent(b.link.split("#")[1], "The file secret key");

  // ---- 3. Request a secret --------------------------------------------------
  const requester = await newPage(browser, "request");
  await requester.goto(`${BASE}/request`);
  await requester.fill("#q-note", "Please send the WordPress admin login for acme.com");
  await requester.click("#q-btn");
  await shown(requester, "#q-created");
  const clientLink = await requester.inputValue("#q-client-link");
  const inboxLink = await requester.inputValue("#q-inbox-link");
  assert.match(clientLink, /\/r#[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{87}$/);
  assert.match(inboxLink, /\/i#[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/);
  await requester.screenshot({ path: art("06-request-created.png"), fullPage: true });

  const client = await newPage(browser, "submit");
  await client.goto(clientLink);
  await shown(client, "#r-compose");
  assert.equal(await client.textContent("#r-note"), "Please send the WordPress admin login for acme.com");
  await client.screenshot({ path: art("07-submit.png"), fullPage: true });
  const codes = Buffer.from("backup codes: 1111-2222 3333-4444\n");
  await client.fill("#r-secret", "admin / correct-horse-battery-staple");
  await client.setInputFiles("#r-file", { name: "backup-codes.txt", mimeType: "text/plain", buffer: codes });
  await client.click("#r-btn");
  await shown(client, "#r-sent");

  const reuse = await newPage(browser, "submit-again");
  await reuse.goto(clientLink);
  await shown(reuse, "#r-closed");
  assert.match(await reuse.textContent("#r-closed-title"), /already answered/);

  const inbox = await newPage(browser, "inbox");
  await inbox.goto(inboxLink);
  await shown(inbox, "#i-view");
  assert.equal(await inbox.textContent("#i-badge"), "Response ready");
  await inbox.screenshot({ path: art("08-inbox.png"), fullPage: true });
  await inbox.click("#i-open");
  await shown(inbox, "#i-content");
  assert.equal(await inbox.textContent("#i-text"), "admin / correct-horse-battery-staple");
  const [codesDownload] = await Promise.all([inbox.waitForEvent("download"), inbox.click("#i-download")]);
  assert.deepEqual(await readFile(await codesDownload.path()), codes);
  await inbox.screenshot({ path: art("09-inbox-opened.png"), fullPage: true });

  const [Q, d] = inboxLink.split("#")[1].split(".");
  assertNeverSent(Q, "The request link secret");
  assertNeverSent(d, "The requester's private key");
  assertNeverSent("correct-horse", "The submitted plaintext");

  // ---- 4. Destroy early -------------------------------------------------------
  const c = await createSecret(sender, { text: "to be destroyed" });
  const manager = await newPage(browser, "destroy");
  await manager.goto(c.manage);
  await shown(manager, "#m-view");
  await manager.click("#m-destroy");
  await manager.click("dialog .btn.danger");
  await manager.waitForFunction(() => document.querySelector("#m-badge")?.textContent === "Destroyed");
  const late = await newPage(browser, "reveal-destroyed");
  await late.goto(c.link);
  await shown(late, "#v-gone");
  assert.match(await late.textContent("#v-gone-title"), /destroyed/);

  // ---- 5. Broken links, dark mode and mobile -----------------------------------
  const broken = await newPage(browser, "broken");
  await broken.goto(`${BASE}/s#not-a-key`);
  await shown(broken, "#v-gone");
  assert.match(await broken.textContent("#v-gone-title"), /incomplete/);

  const dark = await newPage(browser, "dark", { colorScheme: "dark" });
  await dark.goto(`${BASE}/`);
  await dark.screenshot({ path: art("10-dark.png"), fullPage: true });
  const mobile = await newPage(browser, "mobile", { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  await mobile.goto(`${BASE}/`);
  await mobile.screenshot({ path: art("11-mobile.png"), fullPage: true });
  await mobile.goto(`${BASE}/security`);
  await mobile.screenshot({ path: art("12-security-mobile.png"), fullPage: true });
}

await mkdir(ARTIFACTS, { recursive: true });
const server = LIVE ? null : await startServer();
// E2E_HOST_MAP="host ip" pins DNS (useful right after a deploy, before caches update).
const hostMap = process.env.E2E_HOST_MAP;
const browser = await chromium.launch({ args: hostMap ? [`--host-resolver-rules=MAP ${hostMap}`] : [] });
try {
  await run(browser);
  const unexpected = issues.filter((issue) => !EXPECTED.some((pattern) => pattern.test(issue)));
  if (unexpected.length) {
    console.error("Console problems:\n" + unexpected.join("\n"));
    process.exitCode = 1;
  } else {
    console.log("E2E passed: all flows work, no console errors or CSP violations, no key material sent.");
  }
} catch (error) {
  console.error(error);
  if (issues.length) console.error("Console problems:\n" + issues.join("\n"));
  process.exitCode = 1;
} finally {
  await browser.close();
  server?.kill("SIGTERM");
}
