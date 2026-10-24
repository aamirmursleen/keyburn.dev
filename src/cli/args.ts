import { CliError } from "./errors";

export interface Args {
  command: string;
  positionals: string[];
  flags: Map<string, string | true>;
  rest: string[];
}

const VALUE_FLAGS = new Set(["--file", "--attach", "--views", "--expires", "--ttl", "--only"]);
const BOOL_FLAGS = new Set(["--json", "--all", "--passphrase", "--passphrase-prompt", "--help", "-h"]);

export function parseArgs(argv: string[]): Args {
  const [command = "help", ...tail] = argv;
  const positionals: string[] = [];
  const flags = new Map<string, string | true>();
  let rest: string[] = [];
  for (let i = 0; i < tail.length; i++) {
    const arg = tail[i] as string;
    if (arg === "--") {
      rest = tail.slice(i + 1);
      break;
    }
    if (VALUE_FLAGS.has(arg)) {
      const value = tail[++i];
      if (value === undefined) throw new CliError("usage", `${arg} needs a value.`);
      flags.set(arg, value);
    } else if (BOOL_FLAGS.has(arg)) {
      flags.set(arg, true);
    } else if (arg.startsWith("--")) {
      throw new CliError("usage", `Unknown option ${arg}. Run: osss help`);
    } else {
      positionals.push(arg);
    }
  }
  return { command, positionals, flags, rest };
}

/** Durations such as 15m, 1h or 3d, in milliseconds. */
export function duration(value: string | true | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const m = typeof value === "string" ? /^(\d{1,4})(m|h|d)$/.exec(value) : null;
  if (!m) throw new CliError("usage", "Durations look like 15m, 1h or 3d.");
  return Number(m[1]) * { m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2] as "m" | "h" | "d"];
}
