import { existsSync } from "node:fs";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CliError } from "../../src/cli/errors";
import { planEnv, runWithSecret } from "../../src/cli/run";
import type { LocalItem } from "../../src/cli/vault";

const base = { PATH: process.env.PATH, HOME: "/home/me", OSSS_HOME: "/x", osss_other: "y", KEEP: "1" };

function item(text: string, file: LocalItem["file"] = null): LocalItem {
  return { v: 1, text, file, origin: "https://secret.nafran.com", openedAt: 0 };
}

function collect(): { stream: PassThrough; text: () => string } {
  const stream = new PassThrough();
  let text = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => (text += chunk));
  return { stream, text: () => text };
}

describe("planEnv", () => {
  it("exports safe variables and drops the tool's own settings", () => {
    const plan = planEnv(item("API_KEY=abc123xyz\nNODE_OPTIONS=--require=evil\nREGION=eu"), base, null);
    expect(plan.exported).toEqual(["API_KEY", "REGION"]);
    expect(plan.env.API_KEY).toBe("abc123xyz");
    expect(plan.env.NODE_OPTIONS).toBeUndefined();
    expect(plan.env.KEEP).toBe("1");
    expect(plan.env.HOME).toBe("/home/me");
    expect(plan.env.OSSS_HOME).toBeUndefined();
    expect(plan.env.osss_other).toBeUndefined();
    expect(plan.values).toEqual(["abc123xyz", "eu"]);
  });

  it("limits variables with --only", () => {
    const plan = planEnv(item("A=1111111\nB=2222222"), base, ["B"]);
    expect(plan.exported).toEqual(["B"]);
    expect(plan.env.A).toBeUndefined();
  });

  it("passes a plain secret as OSSS_SECRET", () => {
    const plan = planEnv(item("correct horse battery staple"), base, null);
    expect(plan.exported).toEqual(["OSSS_SECRET"]);
    expect(plan.env.OSSS_SECRET).toBe("correct horse battery staple");
    expect(planEnv(item("plain text value"), base, ["OTHER"]).exported).toEqual([]);
    expect(planEnv(item(""), base, null).exported).toEqual([]);
  });

  it("refuses a plain secret containing NUL", () => {
    expect(() => planEnv(item("bad\u0000secret"), base, null)).toThrow(CliError);
  });
});

describe("runWithSecret", () => {
  const node = process.execPath;
  let home: string;
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "osss-run-"));
  });
  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("runs the command with the secret and redacts it from output", async () => {
    const out = collect();
    const err = collect();
    const code = await runWithSecret(
      item("API_KEY=s3cr3t-token-value"),
      node,
      ["-e", "console.log('key=' + process.env.API_KEY); console.error(process.env.API_KEY.length); process.exit(3)"],
      { home, only: null, stdout: out.stream, stderr: err.stream, baseEnv: base },
    );
    expect(code).toBe(3);
    expect(out.text()).toBe("key=[redacted]\n");
    expect(err.text()).toBe("18\n");
  });

  it("gives an attached file as OSSS_SECRET_FILE and removes it afterwards", async () => {
    const out = collect();
    const script = [
      "const fs = require('fs');",
      "const p = process.env.OSSS_SECRET_FILE;",
      "console.log(fs.readFileSync(p, 'utf8') === 'hi' ? 'content ok' : 'bad');",
      "if (process.platform !== 'win32') console.log((fs.statSync(p).mode & 0o777).toString(8));",
      "console.log(p);",
    ].join("\n");
    const code = await runWithSecret(item("", { name: "a.txt", type: "text/plain", data: "aGk" }), node, ["-e", script], {
      home,
      only: null,
      stdout: out.stream,
      stderr: collect().stream,
      baseEnv: base,
    });
    expect(code).toBe(0);
    const lines = out.text().trim().split("\n");
    expect(lines[0]).toBe("content ok");
    if (process.platform !== "win32") expect(lines[1]).toBe("600");
    const path = lines[lines.length - 1]!;
    expect(path.startsWith(join(home, "tmp"))).toBe(true);
    expect(existsSync(path)).toBe(false);
    expect(await readdir(join(home, "tmp"))).toEqual([]);
  });

  it("returns and removes the attachment when the command exits, even if a background process keeps its output open", async () => {
    const out = collect();
    const started = Date.now();
    const script = [
      "const { spawn } = require('child_process');",
      // A grandchild inherits stdout and outlives the command by 20 seconds.
      "spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20000)'], { stdio: ['ignore', 'inherit', 'inherit'], detached: true }).unref();",
      "console.log('started');",
    ].join("\n");
    const code = await runWithSecret(item("", { name: "a.txt", type: "text/plain", data: "aGk" }), node, ["-e", script], {
      home,
      only: null,
      stdout: out.stream,
      stderr: collect().stream,
      baseEnv: base,
    });
    expect(code).toBe(0);
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(out.text()).toBe("started\n");
    expect(await readdir(join(home, "tmp"))).toEqual([]);
  });

  it("redacts the lines of a text attachment from output", async () => {
    const out = collect();
    const data = Buffer.from("DB_PASSWORD=attached-secret-value\nshort\n").toString("base64url");
    const script = "const t = require('fs').readFileSync(process.env.OSSS_SECRET_FILE, 'utf8'); process.stdout.write(t); console.log('first: ' + t.split('\\n')[0]);";
    await runWithSecret(item("", { name: ".env", type: "text/plain", data }), node, ["-e", script], {
      home,
      only: null,
      stdout: out.stream,
      stderr: collect().stream,
      baseEnv: base,
    });
    expect(out.text()).toBe("[redacted]\nfirst: [redacted]\n");
  });

  it("reports a command that can't be started", async () => {
    const err = collect();
    const code = await runWithSecret(item("x=1234567"), "osss-definitely-not-a-command", [], {
      home,
      only: null,
      stdout: collect().stream,
      stderr: err.stream,
      baseEnv: base,
    });
    expect(code).toBe(127);
    expect(err.text()).toMatch(/couldn't start osss-definitely-not-a-command \(not found\)/);
  });

  it("returns 128 + the signal number when the command is killed", async () => {
    if (process.platform === "win32") return;
    const code = await runWithSecret(item("x=1234567"), node, ["-e", "process.kill(process.pid, 'SIGKILL')"], {
      home,
      only: null,
      stdout: collect().stream,
      stderr: collect().stream,
      baseEnv: base,
    });
    expect(code).toBe(128 + 9);
  });

  it("doesn't run a shell", async () => {
    const out = collect();
    await runWithSecret(item("x=1234567"), node, ["-e", "console.log(process.argv[1])", "$(echo injected)"], {
      home,
      only: null,
      stdout: out.stream,
      stderr: collect().stream,
      baseEnv: base,
    });
    expect(out.text()).toBe("$(echo injected)\n");
  });
});
