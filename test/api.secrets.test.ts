import { describe, expect, it } from "vitest";
import {
  b64urlEncode,
  call,
  decryptText,
  freshIp,
  makeSecret,
  randomBytes,
  runAlarm,
  shiftTime,
  storedKeys,
  tokenHash,
} from "./helpers";
import { LIMITS } from "../src/shared/protocol";

const HOUR = 3600_000;

describe("secret lifecycle", () => {
  it("creates, opens exactly once, then reports it as viewed", async () => {
    const secret = await makeSecret({ text: "db: s3cr3t 🐑" });
    expect(secret.res.status).toBe(201);
    expect(secret.res.body.success).toBe(true);
    expect(secret.res.body.data.uploadToken).toBeNull();
    expect(secret.res.body.data.expiresAt).toBeGreaterThan(Date.now() + HOUR - 60_000);

    const meta = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(meta.status).toBe(200);
    expect(meta.body.data).toMatchObject({ state: "active", viewsLeft: 1, attemptsLeft: 5, kdf: null, file: null });

    const before = await call("secret/status", { id: secret.id, manageToken: secret.manageToken });
    expect(before.body.data).toMatchObject({ state: "active", views: [], viewsLeft: 1, endedAt: null, passphrase: false });

    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(opened.status).toBe(200);
    expect(opened.body.data.viewsLeft).toBe(0);
    expect(await decryptText(secret, opened.body.data)).toBe("db: s3cr3t 🐑");

    const again = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(again.status).toBe(404);

    const after = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(after.body.data).toMatchObject({ state: "gone", reason: "viewed" });

    const status = await call("secret/status", { id: secret.id, manageToken: secret.manageToken });
    expect(status.body.data.state).toBe("viewed");
    expect(status.body.data.views).toHaveLength(1);
    expect(status.body.data.viewsLeft).toBe(0);

    // The ciphertext is gone from storage; only the tombstone remains.
    expect(await storedKeys("secret", secret.id)).toEqual(["tomb"]);
  });

  it("honours a view limit above one", async () => {
    const secret = await makeSecret({ maxViews: 3 });
    const open = () => call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect((await open()).body.data.viewsLeft).toBe(2);
    expect((await open()).body.data.viewsLeft).toBe(1);
    expect((await open()).body.data.viewsLeft).toBe(0);
    expect((await open()).status).toBe(404);
  });

  it("lets exactly one concurrent reader win a one-time secret", async () => {
    const secret = await makeSecret();
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken }),
      ),
    );
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 404)).toHaveLength(7);
  });

  it("refuses creating the same id twice", async () => {
    const secret = await makeSecret();
    const dup = await call("secret/create", secret.input);
    expect(dup.status).toBe(409);
    expect(dup.body).toEqual({ success: false, error: "conflict" });
  });
});

describe("passphrases", () => {
  it("destroys the secret after five wrong passphrases", async () => {
    const secret = await makeSecret({ passphrase: "orange-tiger-boat" });
    const meta = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(meta.body.data.kdf).toEqual(secret.input.kdf);

    for (let left = LIMITS.passphraseAttempts - 1; left >= 0; left--) {
      const wrong = await call("secret/open", {
        id: secret.id,
        metaToken: secret.metaToken,
        readToken: b64urlEncode(randomBytes(32)),
      });
      expect(wrong.status).toBe(403);
      expect(wrong.body).toEqual({ success: false, error: "wrong_passphrase", attemptsLeft: left });
    }

    const right = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(right.status).toBe(404);
    const gone = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(gone.body.data).toMatchObject({ state: "gone", reason: "locked" });
  });

  it("opens with the right passphrase after some wrong attempts", async () => {
    const secret = await makeSecret({ passphrase: "orange-tiger-boat" });
    await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: b64urlEncode(randomBytes(32)) });
    const meta = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(meta.body.data.attemptsLeft).toBe(4);
    const right = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(right.status).toBe(200);
    expect(await decryptText(secret, right.body.data)).toBe("hunter2");
  });
});

describe("enumeration resistance", () => {
  it("answers identically for unknown ids and wrong link tokens", async () => {
    const secret = await makeSecret();
    const unknown = await call("secret/meta", { id: b64urlEncode(randomBytes(16)), metaToken: secret.metaToken });
    const wrongToken = await call("secret/meta", { id: secret.id, metaToken: b64urlEncode(randomBytes(32)) });
    expect(unknown.status).toBe(404);
    expect(wrongToken.status).toBe(404);
    expect(wrongToken.body).toEqual(unknown.body);

    const openWrong = await call("secret/open", {
      id: secret.id,
      metaToken: b64urlEncode(randomBytes(32)),
      readToken: secret.readToken,
    });
    expect(openWrong.status).toBe(404);
    // A failed lookup must not burn passphrase attempts.
    const meta = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(meta.body.data.attemptsLeft).toBe(5);
  });

  it("does not reveal tombstones without the link token", async () => {
    const secret = await makeSecret();
    await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    const probe = await call("secret/meta", { id: secret.id, metaToken: b64urlEncode(randomBytes(32)) });
    expect(probe.status).toBe(404);
  });
});

describe("expiry and revocation", () => {
  it("expires on the alarm and erases the ciphertext", async () => {
    const secret = await makeSecret();
    await shiftTime("secret", secret.id, 2 * HOUR);
    expect(await runAlarm("secret", secret.id)).toBe(true);
    const meta = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(meta.body.data).toMatchObject({ state: "gone", reason: "expired" });
    expect(await storedKeys("secret", secret.id)).toEqual(["tomb"]);
  });

  it("expires lazily on access even if the alarm is late", async () => {
    const secret = await makeSecret();
    await shiftTime("secret", secret.id, 2 * HOUR);
    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(opened.status).toBe(404);
    const status = await call("secret/status", { id: secret.id, manageToken: secret.manageToken });
    expect(status.body.data.state).toBe("expired");
  });

  it("lets the sender revoke with the manage token only", async () => {
    const secret = await makeSecret();
    const wrong = await call("secret/revoke", { id: secret.id, manageToken: b64urlEncode(randomBytes(32)) });
    expect(wrong.status).toBe(404);

    const revoked = await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
    expect(revoked.status).toBe(200);
    expect(revoked.body.data.state).toBe("revoked");

    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(opened.status).toBe(404);
    // Revoking again is idempotent.
    expect((await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken })).status).toBe(200);
  });

  it("purges the tombstone after the retention window", async () => {
    const secret = await makeSecret();
    await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
    await shiftTime("secret", secret.id, LIMITS.tombstoneRetentionMs + HOUR);
    await runAlarm("secret", secret.id);
    // Only a content-free marker is left, so the id can never be used again.
    expect(await storedKeys("secret", secret.id)).toEqual(["burned"]);
    expect((await call("secret/status", { id: secret.id, manageToken: secret.manageToken })).status).toBe(404);
  });

  it("does not let someone who only knows an id claim it or learn whether it is in use", async () => {
    const existing = await makeSecret();
    // Any hashes the prober can choose don't hash to the target id, so both cases are rejected alike.
    const probe = { ...existing.input, metaHash: await tokenHash(b64urlEncode(randomBytes(32))) };
    const unused = { ...probe, id: b64urlEncode(randomBytes(16)) };
    expect((await call("secret/create", probe)).body).toEqual({ success: false, error: "bad_request" });
    expect((await call("secret/create", unused)).body).toEqual({ success: false, error: "bad_request" });
  });

  it("never lets anyone create a purged secret id again", async () => {
    const secret = await makeSecret({ text: "original" });
    expect((await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken })).status).toBe(200);
    // Anyone holding the old link can rebuild a valid creation body for the same id.
    const again = { ...secret.input, manageHash: await tokenHash(b64urlEncode(randomBytes(32))) };
    expect((await call("secret/create", again)).status).toBe(409);

    await shiftTime("secret", secret.id, LIMITS.tombstoneRetentionMs + HOUR);
    await runAlarm("secret", secret.id);
    expect((await call("secret/create", again)).status).toBe(409);
    expect((await call("secret/meta", { id: secret.id, metaToken: secret.metaToken })).status).toBe(404);
  });
});

/** Same bytes, but with the unused low bits of the last character set. */
function nonCanonical(value: string): string {
  // Only lengths that are not a multiple of 4 have unused trailing bits to corrupt.
  if (value.length % 4 === 0) throw new Error("no unused bits in a full final quantum");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(value.at(-1)!);
  return value.slice(0, -1) + alphabet[last ^ 1];
}

describe("input validation", () => {
  it("rejects malformed creation requests", async () => {
    const secret = await makeSecret();
    // Keep the bound id, so a body that wrongly passed parsing would get 409, not 400.
    const base = { ...secret.input };
    const cases: Record<string, unknown>[] = [
      { ...base, expiresIn: 123 },
      { ...base, maxViews: 0 },
      { ...base, maxViews: 11 },
      { ...base, maxViews: 1.5 },
      { ...base, id: "short" },
      { ...base, metaHash: "not-a-hash" },
      { ...base, iv: b64urlEncode(randomBytes(16)) },
      { ...base, ct: b64urlEncode(randomBytes(500)) },
      { ...base, ct: "!!!" },
      { ...base, kdf: { alg: "PBKDF2-SHA256", iterations: 1000, salt: b64urlEncode(randomBytes(16)) } },
      { ...base, kdf: { alg: "scrypt", iterations: 600000, salt: b64urlEncode(randomBytes(16)) } },
      { ...base, file: { size: 12345, iv: b64urlEncode(randomBytes(12)) } },
      // Files must be padded to at least 1 KiB, like text (512 is Padmé-aligned, so only the floor rejects it).
      { ...base, file: { size: 512 + 16, iv: b64urlEncode(randomBytes(12)) } },
      // Ciphertext must be canonical base64url (unused trailing bits zero).
      { ...base, ct: nonCanonical(base.ct) },
      { ...base, extra: true },
    ];
    for (const body of cases) {
      const res = await call("secret/create", body);
      expect(res.status, JSON.stringify(Object.keys(body))).toBe(400);
      expect(res.body).toEqual({ success: false, error: "bad_request" });
    }
    const { kdf: _kdf, ...missing } = base;
    expect((await call("secret/create", missing)).status).toBe(400);
  });

  it("rejects bad JSON, wrong content types and oversized bodies", async () => {
    expect((await call("secret/meta", null, { raw: "{not json" })).status).toBe(400);
    expect((await call("secret/meta", null, { raw: "[]" })).status).toBe(400);
    const typed = await call("secret/meta", {}, { headers: { "content-type": "text/plain" } });
    expect(typed.status).toBe(415);
    const big = await call("secret/meta", null, { raw: "x".repeat(LIMITS.jsonBodyMaxBytes + 1) });
    expect(big.status).toBe(413);
  });

  it("refuses cross-site requests", async () => {
    const secret = await makeSecret();
    const body = { id: secret.id, metaToken: secret.metaToken };
    expect((await call("secret/meta", body, { headers: { "sec-fetch-site": "cross-site" } })).status).toBe(403);
    expect((await call("secret/meta", body, { headers: { origin: "https://evil.example" } })).status).toBe(403);
    expect((await call("secret/meta", body, { headers: { "sec-fetch-site": "" } })).status).toBe(200);
  });

  it("returns 404 for unknown endpoints and 405 for wrong methods", async () => {
    expect((await call("secret/nope", {})).status).toBe(404);
    const wrongMethod = await call("secret/meta", null, { method: "GET", raw: undefined });
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("allow")).toBe("POST");
  });
});

describe("abuse controls", () => {
  it("rate-limits bursts of creations from one client", async () => {
    const ip = freshIp();
    const statuses: number[] = [];
    for (let i = 0; i < 14; i++) statuses.push((await makeSecret({ ip })).res.status);
    expect(statuses.slice(0, 10).every((s) => s === 201)).toBe(true);
    expect(statuses).toContain(429);
  });
});
