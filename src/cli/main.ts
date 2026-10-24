import { execFileSync } from "node:child_process";
import { closeSync, openSync, realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { ReadStream, WriteStream } from "node:tty";
import { b64urlEncode, utf8Decode, type Bytes } from "../shared/encoding";
import { safeFileName } from "../shared/names";
import { SECRET_EXPIRY_SECONDS, VIEW_CHOICES } from "../shared/protocol";
import { openSecret, revokeSecret, secretStatus, shareSecret, type Receipt } from "./client";
import { parseEnvSecret } from "./envsecret";
import { duration, parseArgs } from "./args";
import { CliError, EXIT_CODES } from "./errors";
import { planHook } from "./hook";
import { Api } from "./http";
import { DEFAULT_ORIGINS, parseReceiptLink, parseSecretLink, trustedOrigins } from "./links";
import { serveMcp, type OpenSummary } from "./mcp";
import { plainFetch } from "./transport";
import { runWithSecret } from "./run";
import {
  DEFAULT_TTL_MS,
  MAX_TTL_MS,
  ensureVault,
  forgetAll,
  forgetItem,
  listItems,
  loadItem,
  osssHome,
  storeItem,
  sweepAttachments,
  sweepExpired,
} from "./vault";
import { VERSION } from "./version";

const HELP = `osss ${VERSION}: open and share One Smart Sheep secret links on this machine.

For AI agents (values are never printed):
  osss open [<link>|-]                   Open a link; store it encrypted locally; print a handle
                                         (no link: asks for it without echo; -: reads standard input)
  osss run <handle> [--only A,B] -- <command> [args...]
                                         Run a command with the secret in its environment
                                         (KEY=VALUE secrets as variables, otherwise OSSS_SECRET;
                                         an attached file as OSSS_SECRET_FILE), output redacted
  osss list                              List local copies (ids and expiry only)
  osss forget <handle|id> | --all        Delete local copies
  osss mcp                               Run the MCP server (stdio)
  osss hook claude-code                  Claude Code UserPromptSubmit hook: opens secret links
                                         pasted into a prompt here and keeps them out of the chat

For people:
  osss reveal <handle>                   Show the value (interactive terminal only)
  osss send [--file PATH] [--attach PATH] [--views 1|2|3|5|10] [--expires 15m|1h|1d|3d|7d]
            [--passphrase | --passphrase-prompt]
                                         Create a link (text from --file or standard input)
  osss status [<receipt>|-]              Show who opened a secret, and when
  osss revoke [<receipt>|-]              Destroy a secret now

Options: --json (machine-readable output), --ttl 1h (local copy lifetime, default 24h, max 7d).
A passphrase is only ever asked for in an interactive terminal, never taken from arguments.`;

function out(text: string): void {
  process.stdout.write(`${text}\n`);
}

async function readStdin(limit: number): Promise<Bytes> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    total += buf.length;
    if (total > limit) throw new CliError("too_large", "Input is too large.");
    chunks.push(buf);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/**
 * A link or receipt argument. "-" reads it from standard input; with no argument at an
 * interactive terminal it is asked for without echo. Both keep it out of process lists and
 * shell history.
 */
async function linkArg(value: string | undefined, what: string): Promise<string> {
  if (value === undefined && process.stdin.isTTY) return promptHidden(`Paste the ${what} (it won't be shown) and press Enter: `);
  if (!value) throw new CliError("usage", `Give the ${what}, or - to read it from standard input.`);
  if (value !== "-") return value;
  return utf8Decode(await readStdin(4096)).split(/\r?\n/)[0] ?? "";
}

/** Asks on the controlling terminal without echo; fails when there is no person at a terminal. */
async function promptHidden(question: string): Promise<string> {
  let readFd: number;
  let writeFd: number;
  try {
    readFd = openSync("/dev/tty", "r");
  } catch {
    throw new CliError(
      "no_terminal",
      "This needs a passphrase, which can only be typed in an interactive terminal. Run this command yourself in a terminal.",
    );
  }
  try {
    writeFd = openSync("/dev/tty", "w");
  } catch {
    closeSync(readFd);
    throw new CliError("no_terminal", "Couldn't use the terminal.");
  }
  // Each stream owns (and closes) its own descriptor.
  const input = new ReadStream(readFd);
  const output = new WriteStream(writeFd);
  try {
    output.write(question);
    input.setRawMode(true);
    input.setEncoding("utf8");
    return await new Promise<string>((resolve, reject) => {
      let value = "";
      input.on("error", () => reject(new CliError("no_terminal", "Couldn't read from the terminal.")));
      input.on("end", () => reject(new CliError("usage", "Cancelled.")));
      input.on("data", (chunk: string) => {
        for (const ch of chunk) {
          if (ch === "\r" || ch === "\n") return resolve(value);
          if (ch === "\u0003" || ch === "\u0004") return reject(new CliError("usage", "Cancelled."));
          if (ch === "\u007f" || ch === "\b") value = Array.from(value).slice(0, -1).join("");
          else if (ch >= " ") value += ch;
        }
      });
    });
  } finally {
    try {
      input.setRawMode(false);
    } catch {
      // the terminal is already gone
    }
    output.end("\n");
    input.destroy();
  }
}

function selfCommand(): string {
  let script = process.argv[1] ?? "osss";
  try {
    script = realpathSync(script);
  } catch {
    // keep as given
  }
  return `"${process.execPath}" "${script}"`;
}

interface Context {
  home: string;
  origins: readonly string[];
  ttlMs: number;
}

async function openToHandle(ctx: Context, linkText: string, allowPrompt: boolean): Promise<OpenSummary> {
  const link = parseSecretLink(linkText, ctx.origins);
  const api = new Api(link.origin, plainFetch);
  // Fail before using up a view if the secret couldn't be stored afterwards.
  await ensureVault(ctx.home);
  let opened;
  try {
    opened = await openSecret(api, link.S, null);
  } catch (error) {
    if (!(error instanceof CliError) || error.code !== "passphrase_required") throw error;
    if (!allowPrompt) {
      throw new CliError(
        "passphrase_required",
        "This secret needs a passphrase. Ask the user to run `osss open` with this link in their own terminal (it asks for the passphrase without showing it) and to give you the handle it prints. Never ask for the passphrase in the chat.",
      );
    }
    opened = await openSecret(api, link.S, await promptHidden("Passphrase: "));
  }
  let stored;
  try {
    stored = await storeItem(
      ctx.home,
      {
        v: 1,
        text: opened.text,
        file: opened.file ? { name: safeFileName(opened.file.name), type: opened.file.type.slice(0, 100), data: b64urlEncode(opened.file.data) } : null,
        origin: link.origin,
        openedAt: Date.now(),
      },
      ctx.ttlMs,
    );
  } catch (error) {
    const reason = error instanceof CliError ? error.message : `${(error as NodeJS.ErrnoException).code ?? "error"} writing to ${ctx.home}`;
    throw new CliError(
      "unsafe_storage",
      `The secret was opened (that view is used up) but couldn't be saved on this computer: ${reason}. Ask the sender for a new link.`,
    );
  }
  const env = parseEnvSecret(opened.text);
  return {
    handle: stored.handle,
    contains: env ? "environment variables" : "text",
    variables: env ? [...env.vars.keys()] : opened.text ? ["OSSS_SECRET"] : [],
    refusedVariables: env?.refused ?? [],
    hasFile: opened.file !== null,
    viewsLeft: opened.viewsLeft,
    localCopyExpiresAt: new Date(stored.expiresAt).toISOString(),
    runCommand: `${selfCommand()} run ${stored.handle} -- <command> [args...]`,
  };
}

/** Puts text on the clipboard where a standard tool exists; best effort. */
function copyToClipboard(text: string): boolean {
  const tools: [string, string[]][] =
    process.platform === "darwin"
      ? [["/usr/bin/pbcopy", []]]
      : process.platform === "win32"
        ? [["clip", []]]
        : [
            ["wl-copy", []],
            ["xclip", ["-selection", "clipboard"]],
          ];
  for (const [command, commandArgs] of tools) {
    try {
      execFileSync(command, commandArgs, { input: text, stdio: ["pipe", "ignore", "ignore"], timeout: 2000 });
      return true;
    } catch {
      // try the next one
    }
  }
  return false;
}

/** How long the hook may spend opening links before it gives up (Claude Code's timeout is longer). */
const HOOK_DEADLINE_MS = 240_000;

/**
 * Claude Code UserPromptSubmit hook. Prints nothing (letting the prompt through) unless the prompt
 * contains a secret link; then it opens the link here and blocks the prompt, so the link never
 * reaches the model, and offers the message back with a handle instead. Anything unexpected
 * blocks the prompt too: this hook fails closed.
 */
async function claudeCodeHook(ctx: Context): Promise<number> {
  const block = (reason: string): number => {
    out(JSON.stringify({ decision: "block", reason, hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true } }));
    return 0;
  };
  let prompt: string;
  try {
    prompt = utf8Decode(await readStdin(16 * 1024 * 1024));
    try {
      const event = JSON.parse(prompt) as { prompt?: unknown };
      if (typeof event.prompt === "string") prompt = event.prompt;
    } catch {
      // not JSON: scan the raw input, so a link is still caught
    }
  } catch {
    return block("osss couldn't read this message to check it for secret links, so it wasn't sent.");
  }
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<null>((resolve) => (timer = setTimeout(() => resolve(null), HOOK_DEADLINE_MS)));
  let plan: Awaited<ReturnType<typeof planHook>> | null;
  try {
    plan = await Promise.race([planHook(prompt, ctx.origins, (link) => openToHandle(ctx, link, false)), deadline]);
  } catch {
    plan = null;
  } finally {
    clearTimeout(timer);
  }
  if (!plan) return block("osss couldn't finish checking this message for secret links, so it wasn't sent. Run `node ~/.osss/osss.mjs list` to see what was opened.");
  if (!plan.block) return 0;
  const copied = copyToClipboard(plan.rewritten);
  return block(`${plan.reason}${copied ? "\n\n(It's on your clipboard: paste it and press Enter.)" : ""}`);
}

function printReceipt(r: Receipt, json: boolean): void {
  if (json) return out(JSON.stringify(r, null, 2));
  out(`State: ${r.state}`);
  out(`Views left: ${r.viewsLeft} of ${r.maxViews}`);
  out(`Expires: ${new Date(r.expiresAt).toISOString()}`);
  for (const v of r.views) out(`Opened ${new Date(v.at).toISOString()}${v.country ? ` from ${v.country}` : ""}`);
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const json = args.flags.has("--json");
  const ctx: Context = {
    home: osssHome(),
    origins: trustedOrigins(process.env.OSSS_ORIGIN),
    ttlMs: duration(args.flags.get("--ttl"), DEFAULT_TTL_MS),
  };
  if (ctx.ttlMs > MAX_TTL_MS) throw new CliError("usage", "The local lifetime can be at most 7 days.");

  switch (args.command) {
    case "open": {
      await sweepExpired(ctx.home);
      const summary = await openToHandle(ctx, await linkArg(args.positionals[0], "secret link"), true);
      if (json) {
        out(JSON.stringify(summary, null, 2));
      } else {
        out("Opened. The secret is stored encrypted on this machine and was not shown.");
        out(`Handle: ${summary.handle}`);
        out(
          summary.contains === "environment variables"
            ? `Contains: ${summary.variables.length} environment variable(s): ${summary.variables.join(", ")}`
            : "Contains: text (available to commands as OSSS_SECRET)",
        );
        if (summary.refusedVariables.length) {
          out(`Not exported (could change how programs run): ${summary.refusedVariables.join(", ")}`);
        }
        if (summary.hasFile) out("Attached file: available to commands as OSSS_SECRET_FILE");
        out(summary.viewsLeft > 0 ? `Views left on the server: ${summary.viewsLeft}` : "The secret is now deleted from the server.");
        out(`Local copy expires: ${summary.localCopyExpiresAt}`);
        out(`Use it:  osss run ${summary.handle} -- <command> [args...]`);
        out(`Forget:  osss forget ${summary.handle}`);
      }
      return 0;
    }
    case "run": {
      const handle = args.positionals[0];
      if (!handle || args.rest.length === 0) throw new CliError("usage", "Usage: osss run <handle> [--only A,B] -- <command> [args...]");
      await sweepExpired(ctx.home);
      const item = await loadItem(ctx.home, handle);
      const only = typeof args.flags.get("--only") === "string" ? (args.flags.get("--only") as string).split(",").map((s) => s.trim()) : null;
      const [command, ...commandArgs] = args.rest as [string, ...string[]];
      await sweepAttachments(ctx.home);
      return runWithSecret(item, command, commandArgs, { home: ctx.home, only, stdout: process.stdout, stderr: process.stderr, baseEnv: process.env });
    }
    case "reveal": {
      if (!process.stdout.isTTY || !process.stdin.isTTY) {
        throw new CliError("no_terminal", "reveal only works in an interactive terminal. Agents: use `osss run` instead.");
      }
      const item = await loadItem(ctx.home, args.positionals[0] ?? "");
      process.stderr.write("Showing the secret. Anyone who can see this screen or its history can read it.\n");
      out(item.text);
      if (item.file) process.stderr.write(`It also has an attached file (${item.file.name}); use osss run to pass it to a program.\n`);
      return 0;
    }
    case "list": {
      await sweepExpired(ctx.home);
      const items = await listItems(ctx.home);
      if (json) out(JSON.stringify(items.map((i) => ({ id: i.id, expiresAt: new Date(i.expiresAt).toISOString() })), null, 2));
      else if (items.length === 0) out("No local copies.");
      else for (const i of items) out(`${i.id}  expires ${new Date(i.expiresAt).toISOString()}`);
      return 0;
    }
    case "forget": {
      const count = args.flags.has("--all")
        ? await forgetAll(ctx.home)
        : (await forgetItem(ctx.home, args.positionals[0] ?? "")) ? 1 : 0;
      out(json ? JSON.stringify({ forgotten: count }) : `Forgot ${count} local cop${count === 1 ? "y" : "ies"}.`);
      return 0;
    }
    case "send": {
      const filePath = args.flags.get("--file");
      const attachPath = args.flags.get("--attach");
      let text = "";
      if (typeof filePath === "string") text = utf8Decode(new Uint8Array(await readFile(filePath)));
      else if (!process.stdin.isTTY) text = utf8Decode(await readStdin(1024 * 1024));
      const attach = typeof attachPath === "string" ? new Uint8Array(await readFile(attachPath)) : null;
      if (!text && !attach) throw new CliError("usage", "Give the secret on standard input or with --file, and/or a file with --attach.");
      const views = Number(args.flags.get("--views") ?? 1);
      if (!(VIEW_CHOICES as readonly number[]).includes(views)) throw new CliError("usage", "--views must be 1, 2, 3, 5 or 10.");
      const expiresIn = duration(args.flags.get("--expires"), 86_400_000) / 1000;
      if (!(SECRET_EXPIRY_SECONDS as readonly number[]).includes(expiresIn)) throw new CliError("usage", "--expires must be 15m, 1h, 1d, 3d or 7d.");
      const typed = args.flags.has("--passphrase-prompt");
      const passphrase = typed ? await promptHidden("Passphrase for the recipient: ") : args.flags.has("--passphrase");
      if (typeof passphrase === "string" && passphrase.length < 8) throw new CliError("usage", "Use a passphrase of at least 8 characters.");
      const origin = ctx.origins.length > DEFAULT_ORIGINS.length ? (ctx.origins[ctx.origins.length - 1] as string) : (DEFAULT_ORIGINS[0] as string);
      const shared = await shareSecret(new Api(origin, plainFetch), {
        text,
        file: attach ? { name: basename(attachPath as string), type: "application/octet-stream", data: attach } : null,
        views: views as (typeof VIEW_CHOICES)[number],
        expiresIn: expiresIn as (typeof SECRET_EXPIRY_SECONDS)[number],
        passphrase: passphrase === false ? null : passphrase,
      });
      // A passphrase the person just typed is never printed back; a generated one is shown once.
      const shownPassphrase = typed ? null : shared.passphrase;
      if (json) {
        out(JSON.stringify({ ...shared, passphrase: shownPassphrase, expiresAt: new Date(shared.expiresAt).toISOString() }, null, 2));
      } else {
        out(`Secret link: ${shared.link}`);
        if (shownPassphrase) out(`Passphrase:  ${shownPassphrase}   (send it separately)`);
        out(`Receipt:     ${shared.receipt}   (keep this private)`);
        out(`Expires:     ${new Date(shared.expiresAt).toISOString()}`);
      }
      return 0;
    }
    case "status":
    case "revoke": {
      const receipt = parseReceiptLink(await linkArg(args.positionals[0], "receipt link"), ctx.origins);
      const api = new Api(receipt.origin, plainFetch);
      printReceipt(args.command === "status" ? await secretStatus(api, receipt) : await revokeSecret(api, receipt), json);
      return 0;
    }
    case "mcp": {
      await sweepExpired(ctx.home);
      await sweepAttachments(ctx.home);
      // Opening uses a view, so within a session each secret is opened at most once, whichever
      // host its link names (both serve the same secrets): repeated or concurrent calls get the
      // first outcome, success or failure, and never use another view.
      const opened = new Map<string, Promise<OpenSummary>>();
      await serveMcp({
        async open(linkText) {
          const key = b64urlEncode(parseSecretLink(linkText, ctx.origins).S);
          const earlier = opened.get(key);
          if (!earlier) {
            const attempt = openToHandle(ctx, linkText, false);
            opened.set(key, attempt);
            return attempt;
          }
          const summary = await earlier;
          if ((await listItems(ctx.home)).some((i) => summary.handle.startsWith(`osss_${i.id}_`))) return summary;
          throw new CliError(
            "gone",
            "This link was already opened in this session and its local copy has been forgotten. Opening it again would use another view: ask the user to run `osss open` themselves if they want that.",
          );
        },
        list: async () => (await listItems(ctx.home)).map((i) => ({ id: i.id, expiresAt: new Date(i.expiresAt).toISOString() })),
        forget: async (target) => ((await forgetItem(ctx.home, target)) ? 1 : 0),
      });
      return 0;
    }
    case "hook": {
      if (args.positionals[0] !== "claude-code") throw new CliError("usage", "Usage: osss hook claude-code (reads a UserPromptSubmit event on standard input)");
      return claudeCodeHook(ctx);
    }
    case "version":
    case "--version":
      out(VERSION);
      return 0;
    case "help":
    case "--help":
    case "-h":
      out(HELP);
      return 0;
    default:
      throw new CliError("usage", `Unknown command "${args.command}". Run: osss help`);
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    if (error instanceof CliError) {
      process.stderr.write(`osss: ${error.message}\n`);
      process.exitCode = EXIT_CODES[error.code];
    } else {
      process.stderr.write(`osss: unexpected error (${error instanceof Error ? error.name : "unknown"})\n`);
      process.exitCode = 1;
    }
  },
);
