import { describe, expect, it, vi } from "vitest";
import { CliError } from "../../src/cli/errors";
import { planHook } from "../../src/cli/hook";
import { DEFAULT_ORIGINS, trimLink } from "../../src/cli/links";
import type { OpenSummary } from "../../src/cli/mcp";

const KEY = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";
const LINK = `https://secret.nafran.com/s#${KEY}`;

function summary(handle = "osss_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"): OpenSummary {
  return {
    handle,
    contains: "environment variables",
    variables: ["API_KEY"],
    refusedVariables: [],
    hasFile: false,
    viewsLeft: 0,
    localCopyExpiresAt: "2026-10-25T00:00:00.000Z",
    runCommand: `osss run ${handle} -- <command>`,
  };
}

describe("trimLink", () => {
  it("removes punctuation around pasted links", () => {
    expect(trimLink(`<${LINK}>`)).toBe(LINK);
    expect(trimLink(`(${LINK}).`)).toBe(LINK);
    expect(trimLink(`"${LINK}",`)).toBe(LINK);
    expect(trimLink(LINK)).toBe(LINK);
  });
});

describe("planHook", () => {
  it("lets prompts without secret links through untouched", async () => {
    const open = vi.fn();
    for (const prompt of [
      "deploy the site",
      "see https://example.com/s#abc and https://secret.nafran.com/security",
      "the page https://secret.nafran.com/ is fine",
      "https://evil.example/s#" + KEY,
    ]) {
      expect(await planHook(prompt, DEFAULT_ORIGINS, open)).toEqual({ block: false, reason: "", rewritten: prompt });
    }
    expect(open).not.toHaveBeenCalled();
  });

  it("opens secret links locally, blocks the prompt and offers it back with a handle", async () => {
    const open = vi.fn(async () => summary());
    const plan = await planHook(`Deploy with the token in ${LINK}. Then tell me (and use ${LINK} only once).`, DEFAULT_ORIGINS, open);
    expect(open).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledWith(LINK);
    expect(plan.block).toBe(true);
    expect(plan.rewritten).not.toContain(KEY);
    expect(plan.reason).not.toContain(KEY);
    expect(plan.rewritten).toBe(
      "Deploy with the token in osss_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB (osss handle; variables: API_KEY). Then tell me (and use osss_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB (osss handle; variables: API_KEY) only once).",
    );
    expect(plan.reason).toMatch(/not sent to Claude/);
    expect(plan.reason).toContain(plan.rewritten);
  });

  it("catches links without a scheme, in brackets and on the second host, and opens each secret once", async () => {
    const open = vi.fn(async (_link: string) => summary());
    const plan = await planHook(`a secret.nafran.com/s#${KEY} b <https://SECRETS.nafran.com/s#${KEY}> c ${LINK}`, DEFAULT_ORIGINS, open);
    expect(plan.block).toBe(true);
    expect(open.mock.calls.map((c) => c[0])).toEqual([`https://secret.nafran.com/s#${KEY}`]);
    expect(plan.rewritten).not.toContain(KEY);
    expect(plan.rewritten.match(/osss_A{16}_B{43} \(osss handle/g)).toHaveLength(3);
  });

  it("opens different secrets in parallel", async () => {
    const other = `https://secret.nafran.com/s#${"Z".repeat(43)}`;
    let inFlight = 0;
    let most = 0;
    const open = vi.fn(async (link: string) => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 20));
      inFlight--;
      return summary(link === LINK ? "osss_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" : "osss_CCCCCCCCCCCCCCCC_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");
    });
    const plan = await planHook(`${LINK} and ${other}`, DEFAULT_ORIGINS, open);
    expect(most).toBe(2);
    expect(plan.rewritten).toMatch(/^osss_A{16}_B{43} .* and osss_C{16}_D{43} /);
  });

  it("blocks receipt, request and inbox links without opening them", async () => {
    const open = vi.fn();
    const plan = await planHook(`check https://secret.nafran.com/m#${KEY}.${KEY} and https://secret.nafran.com/i#${KEY}.${KEY}`, DEFAULT_ORIGINS, open);
    expect(plan.block).toBe(true);
    expect(open).not.toHaveBeenCalled();
    expect(plan.rewritten).toBe("check [private link removed] and [private link removed]");
  });

  it("still blocks when a link can't be opened", async () => {
    const gone = await planHook(LINK, DEFAULT_ORIGINS, async () => Promise.reject(new CliError("gone", "This secret is no longer available (viewed).")));
    expect(gone).toMatchObject({ block: true, rewritten: "[secret link removed]" });
    expect(gone.reason).toContain("no longer available");

    const locked = await planHook(LINK, DEFAULT_ORIGINS, async () => Promise.reject(new CliError("passphrase_required", "x")));
    expect(locked.reason).toMatch(/another terminal/);

    const broken = await planHook(LINK, DEFAULT_ORIGINS, async () => Promise.reject(new Error("boom s3cr3t")));
    expect(broken.block).toBe(true);
    expect(broken.reason).not.toContain("s3cr3t");
  });
});
