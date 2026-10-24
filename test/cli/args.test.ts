import { describe, expect, it } from "vitest";
import { duration, parseArgs } from "../../src/cli/args";
import { CliError } from "../../src/cli/errors";

describe("parseArgs", () => {
  it("splits command, positionals, flags and the command after --", () => {
    const a = parseArgs(["run", "osss_handle", "--only", "A,B", "--", "node", "--json", "-e", "x"]);
    expect(a.command).toBe("run");
    expect(a.positionals).toEqual(["osss_handle"]);
    expect(a.flags.get("--only")).toBe("A,B");
    expect(a.flags.has("--json")).toBe(false);
    expect(a.rest).toEqual(["node", "--json", "-e", "x"]);
  });

  it("defaults to help and accepts - as a positional", () => {
    expect(parseArgs([]).command).toBe("help");
    const a = parseArgs(["open", "-", "--json"]);
    expect(a.positionals).toEqual(["-"]);
    expect(a.flags.get("--json")).toBe(true);
  });

  it("refuses unknown options and missing values", () => {
    expect(() => parseArgs(["send", "--views"])).toThrow(CliError);
    expect(() => parseArgs(["send", "--views=3"])).toThrow(/Unknown option/);
    expect(() => parseArgs(["open", "--passphrase-value", "x"])).toThrow(/Unknown option/);
  });
});

describe("duration", () => {
  it("reads minutes, hours and days", () => {
    expect(duration(undefined, 42)).toBe(42);
    expect(duration("15m", 0)).toBe(900_000);
    expect(duration("1h", 0)).toBe(3_600_000);
    expect(duration("7d", 0)).toBe(604_800_000);
  });

  it("refuses anything else", () => {
    for (const bad of ["", "1", "1w", "-1h", "1.5h", "99999d", true] as const) {
      expect(() => duration(bad, 0), String(bad)).toThrow(CliError);
    }
  });
});
