import { spawn } from "node:child_process";
import { open, rm } from "node:fs/promises";
import { constants } from "node:os";
import { join } from "node:path";
import { b64urlDecode } from "../shared/encoding";
import { makeRedactor, parseEnvSecret } from "./envsecret";
import { CliError } from "./errors";
import { attachmentDir, type LocalItem } from "./vault";

export interface EnvPlan {
  env: NodeJS.ProcessEnv;
  exported: string[];
  values: string[];
}

/** Builds the child's environment: safe KEY=VALUE names, or OSSS_SECRET for plain secrets. */
export function planEnv(item: LocalItem, base: NodeJS.ProcessEnv, only: readonly string[] | null): EnvPlan {
  const env: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(base)) if (!name.toUpperCase().startsWith("OSSS_")) env[name] = value;
  const exported: string[] = [];
  const values: string[] = [];
  const parsed = parseEnvSecret(item.text);
  if (parsed) {
    for (const [name, value] of parsed.vars) {
      if (only && !only.includes(name)) continue;
      env[name] = value;
      exported.push(name);
      values.push(value);
    }
  } else if (item.text.length > 0 && (!only || only.includes("OSSS_SECRET"))) {
    if (item.text.includes("\0")) throw new CliError("usage", "This secret contains a NUL character, so it can't be passed in an environment variable.");
    env.OSSS_SECRET = item.text;
    exported.push("OSSS_SECRET");
    values.push(item.text);
  }
  return { env, exported, values };
}

/** Line-buffered redaction of a child's output stream; flushes whatever is left when it closes. */
function pipeRedacted(stream: NodeJS.ReadableStream, out: NodeJS.WritableStream, redact: (s: string) => string): Promise<void> {
  return new Promise((resolve) => {
    let buffer = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk: string) => {
      buffer += chunk;
      const lastNewline = buffer.lastIndexOf("\n");
      if (lastNewline >= 0) {
        out.write(redact(buffer.slice(0, lastNewline + 1)));
        buffer = buffer.slice(lastNewline + 1);
      } else if (buffer.length > 1024 * 1024) {
        out.write(redact(buffer));
        buffer = "";
      }
    });
    stream.on("error", () => undefined);
    stream.on("close", () => {
      if (buffer) out.write(redact(buffer));
      buffer = "";
      resolve();
    });
  });
}

/** A text attachment's content (up to 1 MiB of UTF-8), so its lines are redacted too. */
function attachmentText(item: LocalItem): string[] {
  if (!item.file) return [];
  const bytes = b64urlDecode(item.file.data);
  if (bytes.length > 1024 * 1024) return [];
  try {
    return [new TextDecoder("utf-8", { fatal: true }).decode(bytes)];
  } catch {
    return [];
  }
}

const FORWARDED: NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];
/** After the command exits, how long to keep reading output still in its pipes. */
const DRAIN_MS = 2000;

export interface RunOptions {
  /** The osss home; an attached file is written under it while the command runs. */
  home: string;
  only: readonly string[] | null;
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
  baseEnv: NodeJS.ProcessEnv;
}

/**
 * Runs `command` (no shell) with the secret in its environment. An attached file is written to
 * a private directory (OSSS_SECRET_FILE) and removed as soon as the command exits, even if the
 * command left background processes holding its output open. Returns the command's exit code.
 */
export async function runWithSecret(item: LocalItem, command: string, args: readonly string[], options: RunOptions): Promise<number> {
  const plan = planEnv(item, options.baseEnv, options.only);
  let dir: string | null = null;
  try {
    if (item.file) {
      dir = await attachmentDir(options.home);
      const path = join(dir, "attachment");
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile(b64urlDecode(item.file.data));
      } finally {
        await handle.close();
      }
      plan.env.OSSS_SECRET_FILE = path;
    }
    const redact = makeRedactor([...plan.values, ...attachmentText(item)]);
    const child = spawn(command, [...args], { env: plan.env, stdio: ["inherit", "pipe", "pipe"], shell: false });
    // Pass signals on and wait for the command to end, so the attachment is always removed.
    const forward = (signal: NodeJS.Signals) => child.kill(signal);
    for (const signal of FORWARDED) process.on(signal, forward);
    try {
      const exited = new Promise<number>((resolve) => {
        child.on("error", (error: NodeJS.ErrnoException) => {
          options.stderr.write(`osss: couldn't start ${command}${error.code === "ENOENT" ? " (not found)" : ""}\n`);
          resolve(127);
        });
        child.on("exit", (code, signal) => resolve(code ?? (signal ? 128 + (constants.signals[signal] ?? 15) : 1)));
      });
      const drained = Promise.all([
        child.stdout ? pipeRedacted(child.stdout, options.stdout, redact) : Promise.resolve(),
        child.stderr ? pipeRedacted(child.stderr, options.stderr, redact) : Promise.resolve(),
      ]);
      const code = await exited;
      // A background process started by the command may keep the pipes open indefinitely:
      // stop reading after a short grace period instead of waiting for it.
      let timer: NodeJS.Timeout | undefined;
      await Promise.race([drained, new Promise<void>((resolve) => (timer = setTimeout(resolve, DRAIN_MS)))]);
      clearTimeout(timer);
      child.stdout?.destroy();
      child.stderr?.destroy();
      await drained;
      return code;
    } finally {
      for (const signal of FORWARDED) process.off(signal, forward);
    }
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true });
  }
}
