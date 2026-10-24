import { describe, expect, it } from "vitest";
import {
  b64urlDecode,
  b64urlEncode,
  isB64url,
  utf8Decode,
  utf8Encode,
} from "../src/shared/encoding";
import {
  aad,
  boundId,
  filePaddedLength,
  frame,
  generatePassphrase,
  inboxToken,
  newRequester,
  openFile,
  openPayload,
  padme,
  passphraseBits,
  randomBytes,
  requestAddress,
  requesterKeys,
  seal,
  sealFile,
  sealPayload,
  secretAddress,
  secretKeys,
  senderKeys,
  tokenHash,
  unframe,
} from "../src/shared/crypto";
import { LIMITS, type KdfParams, type Payload } from "../src/shared/protocol";

const FAST_KDF = (salt = randomBytes(16)): KdfParams => ({
  alg: "PBKDF2-SHA256",
  iterations: 1000,
  salt: b64urlEncode(salt),
});

const payload = (text: string, file: Payload["file"] = null): Payload => ({ v: 1, text, file });

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    for (let n = 0; n < 70; n++) {
      const bytes = randomBytes(n);
      expect(b64urlDecode(b64urlEncode(bytes))).toEqual(bytes);
    }
  });

  it("round-trips large buffers without blowing the stack", () => {
    const big = randomBytes(300_000);
    expect(b64urlDecode(b64urlEncode(big))).toEqual(big);
  });

  it("rejects padding, foreign characters, bad lengths and non-canonical input", () => {
    for (const bad of ["AA==", "A+B/", "A", "AB", "a b", "abc$"]) {
      expect(() => b64urlDecode(bad)).toThrow();
    }
  });

  it("checks exact decoded length", () => {
    const token = b64urlEncode(randomBytes(32));
    expect(isB64url(token, 32)).toBe(true);
    expect(isB64url(token, 16)).toBe(false);
    expect(isB64url(token + "A", 32)).toBe(false);
    expect(isB64url(123, 32)).toBe(false);
  });

  it("decodes UTF-8 strictly", () => {
    expect(utf8Decode(utf8Encode("héllo 🐑"))).toBe("héllo 🐑");
    expect(() => utf8Decode(new Uint8Array([0xff, 0xfe]))).toThrow();
  });
});

describe("Padmé padding", () => {
  it("matches reference values", () => {
    expect(padme(0)).toBe(0);
    expect(padme(1)).toBe(1);
    expect(padme(9)).toBe(10);
    expect(padme(1024)).toBe(1024);
    expect(padme(1025)).toBe(1088);
    expect(padme(65540)).toBe(67584);
    expect(padme(LIMITS.fileMaxBytes)).toBe(LIMITS.fileMaxBytes);
  });

  it("never shrinks, is idempotent and adds at most 12% overhead", () => {
    for (let len = 2; len < 200_000; len += 997) {
      const padded = padme(len);
      expect(padded).toBeGreaterThanOrEqual(len);
      expect(padme(padded)).toBe(padded);
      if (len >= 64) expect((padded - len) / len).toBeLessThanOrEqual(0.12);
    }
  });

  it("rejects invalid lengths", () => {
    expect(() => padme(-1)).toThrow();
    expect(() => padme(1.5)).toThrow();
    expect(() => padme(2 ** 31)).toThrow();
  });
});

describe("framing", () => {
  it("pads short payloads to the minimum frame and round-trips", () => {
    const data = utf8Encode("hunter2");
    const framed = frame(data);
    expect(framed.length).toBe(LIMITS.minFrameBytes);
    expect(unframe(framed)).toEqual(data);
  });

  it("produces Padmé-aligned frames for large payloads", () => {
    const data = randomBytes(50_000);
    const framed = frame(data);
    expect(padme(framed.length)).toBe(framed.length);
    expect(unframe(framed)).toEqual(data);
  });

  it("rejects corrupted length prefixes", () => {
    const framed = frame(utf8Encode("x"));
    new DataView(framed.buffer).setUint32(0, framed.length);
    expect(() => unframe(framed)).toThrow();
    expect(() => unframe(new Uint8Array(3))).toThrow();
  });
});

describe("secret links", () => {
  it("derives a stable address from the link key", async () => {
    const S = randomBytes(32);
    const a = await secretAddress(S);
    const b = await secretAddress(S);
    expect(a).toEqual(b);
    expect(isB64url(a.id, 16)).toBe(true);
    expect(isB64url(a.metaToken, 32)).toBe(true);
    expect((await secretAddress(randomBytes(32))).id).not.toBe(a.id);
  });

  it("rejects link keys of the wrong size", async () => {
    await expect(secretAddress(randomBytes(31))).rejects.toThrow();
  });

  it("binds ids to the capability hash, keeping the older id for existing links", async () => {
    const S = randomBytes(32);
    const a = await secretAddress(S);
    expect(a.id).toBe(await boundId("secret", await tokenHash(a.metaToken)));
    expect(a.id).not.toBe(a.legacyId);
    expect(isB64url(a.legacyId, 16)).toBe(true);
    // Labels separate kinds: the same hash never yields the same id for a request.
    expect(await boundId("request", await tokenHash(a.metaToken))).not.toBe(a.id);
    const Q = randomBytes(32);
    const r = await requestAddress(Q);
    expect(r.id).toBe(await boundId("request", await tokenHash(r.submitToken)));
    expect(r.id).not.toBe(r.legacyId);
  });

  it("encrypts and decrypts a payload bound to its id", async () => {
    const S = randomBytes(32);
    const { id } = await secretAddress(S);
    const keys = await secretKeys(S, null);
    const sealed = await sealPayload(keys.textKey, aad.secretText(id), payload("p@ss 🐑"));
    expect(isB64url(sealed.iv, 12)).toBe(true);
    expect(await openPayload(keys.textKey, aad.secretText(id), sealed)).toEqual(payload("p@ss 🐑"));

    // Same key but a different record id must fail authentication.
    await expect(openPayload(keys.textKey, aad.secretText("A".repeat(22)), sealed)).rejects.toThrow();
    // The file key must not decrypt text.
    await expect(openPayload(keys.fileKey, aad.secretText(id), sealed)).rejects.toThrow();
  });

  it("detects tampering", async () => {
    const S = randomBytes(32);
    const { id } = await secretAddress(S);
    const { textKey } = await secretKeys(S, null);
    const sealed = await sealPayload(textKey, aad.secretText(id), payload("secret"));
    const ct = b64urlDecode(sealed.ct);
    ct[10] = (ct[10] ?? 0) ^ 1;
    await expect(openPayload(textKey, aad.secretText(id), { iv: sealed.iv, ct: b64urlEncode(ct) })).rejects.toThrow();
  });

  it("mixes the passphrase into the read token and the keys", async () => {
    const S = randomBytes(32);
    const kdf = FAST_KDF();
    const plain = await secretKeys(S, null);
    const right = await secretKeys(S, { passphrase: "correct horse", kdf });
    const again = await secretKeys(S, { passphrase: "correct horse", kdf });
    const wrong = await secretKeys(S, { passphrase: "wrong horse", kdf });

    expect(right.readToken).toBe(again.readToken);
    expect(right.readToken).not.toBe(plain.readToken);
    expect(right.readToken).not.toBe(wrong.readToken);

    const { id } = await secretAddress(S);
    const sealed = await sealPayload(right.textKey, aad.secretText(id), payload("x"));
    await expect(openPayload(wrong.textKey, aad.secretText(id), sealed)).rejects.toThrow();
    await expect(openPayload(plain.textKey, aad.secretText(id), sealed)).rejects.toThrow();
    expect((await openPayload(again.textKey, aad.secretText(id), sealed)).text).toBe("x");
  });

  it("normalizes passphrases to NFC", async () => {
    const salt = randomBytes(16);
    const composed = await passphraseBits("café", salt, 1000);
    const decomposed = await passphraseBits("café", salt, 1000);
    expect(composed).toEqual(decomposed);
  });

  it("runs PBKDF2 at the production iteration count", async () => {
    const bits = await passphraseBits("long enough", randomBytes(16), LIMITS.pbkdf2MinIterations);
    expect(bits.length).toBe(32);
  });

  it("rejects oversized payloads before encrypting", async () => {
    const S = randomBytes(32);
    const { textKey } = await secretKeys(S, null);
    const huge = payload("x".repeat(LIMITS.payloadMaxBytes + 1));
    await expect(sealPayload(textKey, aad.secretText("A".repeat(22)), huge)).rejects.toThrow();
  });

  it("refuses to seal payloads with an invalid shape", async () => {
    const { textKey } = await secretKeys(randomBytes(32), null);
    const bogus = { v: 2, text: 5, file: null } as unknown as Payload;
    await expect(sealPayload(textKey, "aad", bogus)).rejects.toThrow();
  });

  it("rejects payloads with an invalid shape after decryption", async () => {
    const { textKey } = await secretKeys(randomBytes(32), null);
    for (const bogus of [{ v: 2, text: "x", file: null }, { v: 1, text: 5, file: null }, { v: 1, text: "x", file: { name: 1 } }, "str"]) {
      const sealed = await seal(textKey, frame(utf8Encode(JSON.stringify(bogus))), "aad");
      await expect(openPayload(textKey, "aad", { iv: b64urlEncode(sealed.iv), ct: b64urlEncode(sealed.ct) })).rejects.toThrow();
    }
  });
});

describe("files", () => {
  it("pads, encrypts and restores file bytes", async () => {
    const S = randomBytes(32);
    const { id } = await secretAddress(S);
    const { fileKey } = await secretKeys(S, null);
    const data = randomBytes(10_000);
    const sealed = await sealFile(fileKey, aad.secretFile(id), data);
    expect(sealed.ct.length).toBe(padme(data.length) + 16);
    expect(await openFile(fileKey, aad.secretFile(id), sealed.iv, sealed.ct, data.length)).toEqual(data);
    await expect(openFile(fileKey, aad.secretFile("B".repeat(22)), sealed.iv, sealed.ct, data.length)).rejects.toThrow();
  });

  it("pads small files to at least 1 KiB so the stored size hides their length", async () => {
    const { fileKey } = await secretKeys(randomBytes(32), null);
    for (const n of [1, 12, 34, 200, 1024]) {
      const sealed = await sealFile(fileKey, "f", randomBytes(n));
      expect(sealed.ct.length, String(n)).toBe(LIMITS.minFrameBytes + 16);
    }
    expect(filePaddedLength(5000)).toBe(padme(5000));
  });

  it("still opens small files sealed before the 1 KiB floor", async () => {
    const { fileKey } = await secretKeys(randomBytes(32), null);
    const data = randomBytes(34);
    const padded = new Uint8Array(padme(data.length));
    padded.set(data);
    const legacy = await seal(fileKey, padded, "f");
    expect(await openFile(fileKey, "f", b64urlEncode(legacy.iv), legacy.ct, data.length)).toEqual(data);
  });

  it("rejects a declared size larger than the decrypted data", async () => {
    const S = randomBytes(32);
    const { fileKey } = await secretKeys(S, null);
    const sealed = await sealFile(fileKey, "f", randomBytes(100));
    await expect(openFile(fileKey, "f", sealed.iv, sealed.ct, 10_000)).rejects.toThrow();
  });
});

describe("tokens", () => {
  it("hashes tokens to 32-byte base64url digests", async () => {
    const token = b64urlEncode(randomBytes(32));
    const h1 = await tokenHash(token);
    expect(h1).toBe(await tokenHash(token));
    expect(isB64url(h1, 32)).toBe(true);
    expect(h1).not.toBe(token);
  });
});

describe("request links", () => {
  it("lets only the requester decrypt what the sender encrypts", async () => {
    const requester = await newRequester();
    expect(requester.pub.length).toBe(65);
    expect(requester.d.length).toBe(32);

    const addr = await requestAddress(requester.Q);
    expect(isB64url(addr.id, 16)).toBe(true);
    expect(isB64url(addr.submitToken, 32)).toBe(true);

    const sender = await senderKeys(requester.pub, requester.Q, addr.id);
    const sealed = await sealPayload(sender.textKey, aad.requestText(addr.id), payload("db password"));

    const mine = await requesterKeys(requester.pub, requester.d, requester.Q, addr.id, sender.ephPub);
    expect((await openPayload(mine.textKey, aad.requestText(addr.id), sealed)).text).toBe("db password");

    // A different requester key pair cannot decrypt.
    const other = await newRequester();
    const theirs = await requesterKeys(other.pub, other.d, requester.Q, addr.id, sender.ephPub);
    await expect(openPayload(theirs.textKey, aad.requestText(addr.id), sealed)).rejects.toThrow();

    // The private key alone is not enough without the link secret Q.
    const noQ = await requesterKeys(requester.pub, requester.d, randomBytes(32), addr.id, sender.ephPub);
    await expect(openPayload(noQ.textKey, aad.requestText(addr.id), sealed)).rejects.toThrow();
  });

  it("derives an inbox token that the client link cannot compute", async () => {
    const requester = await newRequester();
    const token = await inboxToken(requester.Q, requester.d);
    const addr = await requestAddress(requester.Q);
    expect(isB64url(token, 32)).toBe(true);
    expect(token).not.toBe(addr.submitToken);
    expect(await inboxToken(requester.Q, randomBytes(32))).not.toBe(token);
  });

  it("encrypts the requester's note with the link secret", async () => {
    const requester = await newRequester();
    const addr = await requestAddress(requester.Q);
    const sealed = await sealPayload(addr.noteKey, aad.requestNote(addr.id), payload("WP admin please"));
    const again = await requestAddress(requester.Q);
    expect((await openPayload(again.noteKey, aad.requestNote(addr.id), sealed)).text).toBe("WP admin please");
  });

  it("rejects malformed public keys", async () => {
    const requester = await newRequester();
    const addr = await requestAddress(requester.Q);
    await expect(senderKeys(randomBytes(65), requester.Q, addr.id)).rejects.toThrow();
  });
});

describe("passphrase generator", () => {
  it("produces unambiguous grouped passphrases", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const pass = generatePassphrase();
      expect(pass).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){4}$/);
      seen.add(pass);
    }
    expect(seen.size).toBe(200);
  });
});
