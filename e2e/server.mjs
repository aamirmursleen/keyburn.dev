// Starts and stops `wrangler dev` (local Workers, Durable Objects, R2 and rate limiting) for the
// end-to-end runs.

import { spawn } from "node:child_process";
import { rm } from "node:fs/promises";

/**
 * Starts wrangler dev on the port with fresh local state. It runs in its own process group, so
 * stopServer can end npx, wrangler and workerd together.
 */
export async function startServer(port) {
  await rm(`.wrangler/e2e-state-${port}`, { recursive: true, force: true });
  const child = spawn(
    "npx",
    ["wrangler", "dev", "--port", String(port), "--ip", "127.0.0.1", "--local-upstream", `localhost:${port}`, "--persist-to", `.wrangler/e2e-state-${port}`, "--show-interactive-dev-session=false"],
    // OSSS_DEV=1: a local server may run an agent tool build that isn't recorded as a release yet.
    { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, OSSS_DEV: "1" }, detached: true },
  );
  let log = "";
  try {
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
  } catch (error) {
    stopServer(child);
    throw error;
  }
  return child;
}

/**
 * Stops wrangler dev and everything it started. Killing only npx leaves workerd running with the
 * output pipes open, and the test run would never exit.
 */
export function stopServer(child) {
  if (!child) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  child.stdout?.destroy();
  child.stderr?.destroy();
}
