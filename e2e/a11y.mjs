// Accessibility check in a real browser against `wrangler dev`: runs axe-core's WCAG 2.2
// A and AA rules, including colour contrast, on every page and on each state of the secret
// and request flows. Any violation fails the run.
//
// Usage: npm run build && node e2e/a11y.mjs
//        E2E_BASE=https://keyburn.dev node e2e/a11y.mjs   (check a live deployment)

import { spawn } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const PORT = Number(process.env.E2E_A11Y_PORT ?? 8797);
const LIVE = process.env.E2E_BASE?.replace(/\/$/, "");
const BASE = LIVE ?? `http://localhost:${PORT}`;
const AXE = await readFile(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"];

async function startServer() {
  await rm(`.wrangler/e2e-state-${PORT}`, { recursive: true, force: true });
  const child = spawn(
    "npx",
    ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1", "--local-upstream", `localhost:${PORT}`, "--persist-to", `.wrangler/e2e-state-${PORT}`, "--show-interactive-dev-session=false"],
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

const violations = [];
const unsure = [];
let checked = 0;
let pixelChecked = 0;

/** Runs axe on what the page shows right now. */
async function audit(page, label) {
  await page.evaluate(() => document.fonts.ready);
  // axe runs in the page; the pages' strict CSP and Trusted Types are relaxed for this
  // context only (see newPage), never for the site.
  await page.evaluate(AXE);
  const result = await page.evaluate(
    (tags) => window.axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations", "incomplete"] }),
    TAGS,
  );
  checked++;
  for (const v of result.violations) {
    for (const node of v.nodes) violations.push(`[${label}] ${v.id}: ${node.failureSummary?.split("\n").slice(1).join(" ").trim()} @ ${node.target.join(" ")}`);
  }
  // axe can't decide when decorations (pseudo-elements, gradients) sit behind text, so those
  // are measured from pixels instead: hide the text, capture what is really behind it, and
  // check the text colour against that.
  for (const v of result.incomplete.filter((i) => i.id === "color-contrast")) {
    for (const node of v.nodes) {
      const selector = node.target[node.target.length - 1];
      const measured = await pixelContrast(page, selector);
      if (!measured) {
        unsure.push(`[${label}] ${node.target.join(" ")}: ${node.any[0]?.message ?? "needs review"}`);
      } else if (measured.ratio < measured.required) {
        violations.push(`[${label}] color-contrast (measured): ${measured.ratio.toFixed(2)} < ${measured.required} for ${measured.color} on ${measured.background} @ ${selector}`);
      } else {
        pixelChecked++;
      }
    }
  }
}

/**
 * Contrast of an element's text against what is drawn behind it, measured from pixels: the
 * element is captured with and without its text, and every pixel the text changes is compared
 * with the same pixel underneath (10th percentile, so thin decorations can't hide a problem).
 */
async function pixelContrast(page, selector) {
  const info = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el || !el.textContent?.trim()) return null;
    el.scrollIntoView({ block: "center" });
    const box = el.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) return null;
    const style = getComputedStyle(el);
    const size = parseFloat(style.fontSize);
    const bold = Number(style.fontWeight) >= 700;
    return { x: box.x, y: box.y, width: box.width, height: box.height, large: size >= 24 || (bold && size >= 18.66) };
  }, selector);
  if (!info) return null;
  const clip = { x: info.x, y: info.y, width: info.width, height: info.height };
  const shown = await page.screenshot({ clip });
  let hidden;
  try {
    await page.evaluate((sel) => {
      const hide = document.createElement("style");
      hide.id = "a11y-hide";
      hide.textContent = `${sel}, ${sel} * { color: transparent !important; -webkit-text-fill-color: transparent !important; text-shadow: none !important; }`;
      document.head.append(hide);
    }, selector);
    hidden = await page.screenshot({ clip });
  } finally {
    await page.evaluate(() => document.getElementById("a11y-hide")?.remove());
  }
  const ratio = await page.evaluate(
    async ({ a, b }) => {
      const pixels = async (b64) => {
        const img = new Image();
        img.src = `data:image/png;base64,${b64}`;
        await img.decode();
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        return ctx.getImageData(0, 0, img.width, img.height).data;
      };
      const [fg, bg] = [await pixels(a), await pixels(b)];
      const lin = (c) => ((c /= 255) <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
      const lum = (d, i) => 0.2126 * lin(d[i]) + 0.7152 * lin(d[i + 1]) + 0.0722 * lin(d[i + 2]);
      // Glyph pixels: where the text changes the picture. The strongest changes are the solid
      // cores of the letters, whose median is the text colour (edges are anti-aliased blends).
      const glyph = [];
      for (let i = 0; i < fg.length; i += 4) {
        const d = Math.abs(fg[i] - bg[i]) + Math.abs(fg[i + 1] - bg[i + 1]) + Math.abs(fg[i + 2] - bg[i + 2]);
        if (d > 24) glyph.push([d, i]);
      }
      if (glyph.length < 8) return null;
      glyph.sort((x, y) => y[0] - x[0]);
      const cores = glyph.slice(0, Math.max(4, Math.floor(glyph.length * 0.1))).map(([, i]) => lum(fg, i)).sort((x, y) => x - y);
      const text = cores[Math.floor(cores.length / 2)];
      // The text against every pixel behind it, worst 10%.
      const ratios = glyph.map(([, i]) => {
        const k = lum(bg, i);
        return (Math.max(text, k) + 0.05) / (Math.min(text, k) + 0.05);
      });
      ratios.sort((x, y) => x - y);
      return ratios[Math.floor(ratios.length * 0.1)];
    },
    { a: shown.toString("base64"), b: hidden.toString("base64") },
  );
  if (ratio === null) return null;
  return { ratio, required: info.large ? 3 : 4.5, color: "the drawn text", background: "the pixels behind it" };
}

async function newPage(browser, options = {}) {
  const context = await browser.newContext({ bypassCSP: true, reducedMotion: "reduce", deviceScaleFactor: 2, ...options });
  return context.newPage();
}

const shown = (page, selector) => page.waitForSelector(`${selector}:not([hidden])`, { timeout: 30_000 });

async function run(browser) {
  for (const path of ["/", "/request", "/security", "/agents", "/no-such-page"]) {
    const page = await newPage(browser);
    await page.goto(`${BASE}${path}`);
    await audit(page, path);
    if (path === "/") {
      // Open every FAQ answer so its text is checked too.
      for (const q of await page.$$(".faq-q[aria-expanded='false']")) await q.click();
      await audit(page, "/ with FAQ open");
    }
    await page.context().close();
  }

  // Secret: create, open, reveal, receipt.
  const sender = await newPage(browser);
  await sender.goto(`${BASE}/`);
  await sender.fill("#secret", "DEMO_TOKEN=a11y-check");
  await sender.click("#create-btn");
  await shown(sender, "#secret-link");
  await audit(sender, "/ link created");
  const link = await sender.inputValue("#secret-link");
  const manage = await sender.inputValue("#manage-link");
  const recipient = await newPage(browser);
  await recipient.goto(link);
  await shown(recipient, "#v-ready");
  await audit(recipient, "/s ready");
  await recipient.click("#agent-help summary");
  await audit(recipient, "/s agent help open");
  await recipient.click("#v-reveal");
  await shown(recipient, "#v-revealed");
  await audit(recipient, "/s revealed");
  const receipt = await newPage(browser);
  await receipt.goto(manage);
  await receipt.waitForFunction(() => document.querySelector("#m-badge")?.textContent?.trim());
  await audit(receipt, "/m receipt");
  const broken = await newPage(browser);
  await broken.goto(`${BASE}/s#not-a-key`);
  await shown(broken, "#v-gone");
  await audit(broken, "/s gone");

  // Request: create, answer, open.
  const requester = await newPage(browser);
  await requester.goto(`${BASE}/request`);
  await requester.fill("#q-note", "The staging database password, please");
  await requester.click("#q-btn");
  await shown(requester, "#q-client-link");
  await audit(requester, "/request created");
  const clientLink = await requester.inputValue("#q-client-link");
  const inboxLink = await requester.inputValue("#q-inbox-link");
  const client = await newPage(browser);
  await client.goto(clientLink);
  await client.waitForSelector("#r-secret");
  await audit(client, "/r answer form");
  await client.fill("#r-secret", "correct-horse-battery-staple");
  await client.click("#r-btn");
  await client.waitForTimeout(1500);
  await audit(client, "/r answered");
  const inbox = await newPage(browser);
  await inbox.goto(inboxLink);
  await shown(inbox, "#i-open");
  await audit(inbox, "/i ready");
  await inbox.click("#i-open");
  await inbox.waitForTimeout(1500);
  await audit(inbox, "/i opened");

  // Phone width.
  for (const path of ["/", "/s#not-a-key", "/agents"]) {
    const page = await newPage(browser, { viewport: { width: 390, height: 844 } });
    await page.goto(`${BASE}${path}`);
    await page.waitForTimeout(600);
    await audit(page, `${path} (390px)`);
    await page.context().close();
  }
}

const server = LIVE ? null : await startServer();
const browser = await chromium.launch();
try {
  await run(browser);
  for (const note of unsure) console.warn(`review contrast by hand: ${note}`);
  if (violations.length) {
    console.error(`Accessibility violations (WCAG 2.2 A/AA):\n${violations.join("\n")}`);
    process.exitCode = 1;
  } else {
    console.log(
      `A11y passed: ${checked} page states meet WCAG 2.2 A and AA in axe-core, including colour contrast` +
        ` (${pixelChecked} texts over decorations measured from pixels).`,
    );
  }
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  await browser.close();
  server?.kill("SIGTERM");
}
