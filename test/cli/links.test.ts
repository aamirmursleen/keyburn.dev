import { describe, expect, it } from "vitest";
import { CliError } from "../../src/cli/errors";
import { DEFAULT_ORIGINS, links, parseReceiptLink, parseSecretLink, trustedOrigins } from "../../src/cli/links";
import { b64urlEncode } from "../../src/shared/encoding";

const S = new Uint8Array(32).map((_, i) => i * 7);
const KEY = b64urlEncode(S);

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof CliError) return error.code;
    throw error;
  }
  return "no error";
}

describe("trustedOrigins", () => {
  it("defaults to the two production hosts", () => {
    expect(trustedOrigins()).toEqual(DEFAULT_ORIGINS);
    expect(trustedOrigins("")).toEqual(DEFAULT_ORIGINS);
  });

  it("adds only a loopback test server", () => {
    expect(trustedOrigins("http://localhost:8787")).toEqual([...DEFAULT_ORIGINS, "http://localhost:8787"]);
    expect(trustedOrigins("http://127.0.0.1:9000/")).toEqual([...DEFAULT_ORIGINS, "http://127.0.0.1:9000"]);
    expect(trustedOrigins("http://[::1]:9000")).toEqual([...DEFAULT_ORIGINS, "http://[::1]:9000"]);
    for (const bad of [
      "https://evil.example",
      "http://localhost.evil.example",
      "http://user@localhost:8787",
      "http://localhost:8787/path",
      "http://localhost:8787/?q",
      "file:///etc/passwd",
      "not a url",
    ]) {
      expect(codeOf(() => trustedOrigins(bad)), bad).toBe("untrusted_origin");
    }
  });
});

describe("parseSecretLink", () => {
  it("accepts links from the trusted hosts", () => {
    const parsed = parseSecretLink(`https://secret.nafran.com/s#${KEY}`, DEFAULT_ORIGINS);
    expect(parsed.origin).toBe("https://secret.nafran.com");
    expect(parsed.S).toEqual(S);
    expect(parseSecretLink(`  https://SECRETS.nafran.com:443/s#${KEY}\n`, DEFAULT_ORIGINS).origin).toBe("https://secrets.nafran.com");
    expect(parseSecretLink(`<https://secret.nafran.com/s#${KEY}>.`, DEFAULT_ORIGINS).S).toEqual(S);
  });

  it("rejects other hosts, schemes and credentials", () => {
    for (const link of [
      `https://evil.example/s#${KEY}`,
      `http://secret.nafran.com/s#${KEY}`,
      `https://secret.nafran.com.evil.example/s#${KEY}`,
      `https://user:pw@secret.nafran.com/s#${KEY}`,
      `https://secret.nafran.com:8443/s#${KEY}`,
    ]) {
      expect(codeOf(() => parseSecretLink(link, DEFAULT_ORIGINS)), link).toBe("untrusted_origin");
    }
  });

  it("rejects wrong paths, queries and damaged keys", () => {
    for (const link of [
      `https://secret.nafran.com/m#${KEY}`,
      `https://secret.nafran.com/s/#${KEY}`,
      `https://secret.nafran.com/s?x=1#${KEY}`,
      "https://secret.nafran.com/s#short",
      `https://secret.nafran.com/s#${KEY}A`,
      "https://secret.nafran.com/s",
      "secret.nafran.com/s#abc",
      `https://secret.nafran.com/s#${"A".repeat(600)}`,
    ]) {
      expect(codeOf(() => parseSecretLink(link, DEFAULT_ORIGINS)), link).toBe("bad_link");
    }
  });

  it("round-trips with links.secret", () => {
    expect(parseSecretLink(links.secret("https://secret.nafran.com", S), DEFAULT_ORIGINS).S).toEqual(S);
  });
});

describe("parseReceiptLink", () => {
  const id = b64urlEncode(new Uint8Array(16).fill(1));
  const token = b64urlEncode(new Uint8Array(32).fill(2));

  it("accepts a receipt link", () => {
    expect(parseReceiptLink(links.receipt("https://secret.nafran.com", id, token), DEFAULT_ORIGINS)).toEqual({
      origin: "https://secret.nafran.com",
      id,
      manageToken: token,
    });
  });

  it("rejects damaged receipts", () => {
    for (const link of [
      `https://secret.nafran.com/m#${id}`,
      `https://secret.nafran.com/m#${id}.${token}.x`,
      `https://secret.nafran.com/m#${token}.${id}`,
      `https://secret.nafran.com/s#${id}.${token}`,
    ]) {
      expect(codeOf(() => parseReceiptLink(link, DEFAULT_ORIGINS)), link).toBe("bad_link");
    }
  });
});
