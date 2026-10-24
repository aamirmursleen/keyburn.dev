// The OSSS v1 protocol: all encryption happens in the browser with native
// WebCrypto. The server only ever sees ciphertext, random identifiers and
// SHA-256 hashes of capability tokens. See docs/SECURITY.md for the design.

import { b64urlDecode, b64urlEncode, concatBytes, isB64url, utf8Decode, utf8Encode, type Bytes } from "./encoding";
import { LIMITS, PROTOCOL, type KdfParams, type Payload, type Sealed } from "./protocol";

const subtle = crypto.subtle;
const HKDF_SALT = utf8Encode(`${PROTOCOL}/hkdf`);
const KEY_BYTES = 32;
const P256 = { name: "ECDH", namedCurve: "P-256" } as const;

type DeriveParams = Parameters<SubtleCrypto["deriveBits"]>[0];

export function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length);
  // getRandomValues is capped at 65,536 bytes per call.
  for (let i = 0; i < length; i += 65536) {
    crypto.getRandomValues(out.subarray(i, Math.min(length, i + 65536)));
  }
  return out;
}

// ---- Padding ---------------------------------------------------------------

/**
 * Padmé padding (Nikitin et al., PETS 2019): rounds a length up so that
 * ciphertext sizes leak at most O(log log n) bits, with <12% overhead.
 */
export function padme(length: number): number {
  if (!Number.isInteger(length) || length < 0 || length > 2 ** 30) {
    throw new RangeError("Invalid length");
  }
  if (length < 2) return length;
  const e = 31 - Math.clz32(length); // floor(log2(length))
  const s = 32 - Math.clz32(e); // floor(log2(e)) + 1
  const mask = (1 << (e - s)) - 1;
  return (length + mask) & ~mask;
}

/** Length-prefixes a payload and zero-pads it to a Padmé size (min 1 KiB). */
export function frame(payload: Uint8Array): Bytes {
  const out = new Uint8Array(Math.max(LIMITS.minFrameBytes, padme(payload.length + 4)));
  new DataView(out.buffer).setUint32(0, payload.length);
  out.set(payload, 4);
  return out;
}

export function unframe(framed: Uint8Array): Bytes {
  if (framed.length < 4) throw new Error("Invalid frame");
  const length = new DataView(framed.buffer, framed.byteOffset, framed.byteLength).getUint32(0);
  if (length > framed.length - 4) throw new Error("Invalid frame");
  return framed.slice(4, 4 + length);
}

// ---- Primitives ------------------------------------------------------------

export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

/** What the server stores for a capability token: base64url(SHA-256(token)). */
export async function tokenHash(token: string): Promise<string> {
  return b64urlEncode(await sha256(b64urlDecode(token)));
}

async function hkdfBase(ikm: Bytes): Promise<CryptoKey> {
  return subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits", "deriveKey"]);
}

function hkdfParams(info: string): DeriveParams {
  return { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: utf8Encode(info) } as DeriveParams;
}

export async function hkdfBits(ikm: Bytes, info: string, bits: number): Promise<Bytes> {
  return new Uint8Array(await subtle.deriveBits(hkdfParams(info), await hkdfBase(ikm), bits));
}

export async function hkdfAesKey(ikm: Bytes, info: string): Promise<CryptoKey> {
  return subtle.deriveKey(hkdfParams(info), await hkdfBase(ikm), { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function passphraseBits(passphrase: string, salt: Bytes, iterations: number): Promise<Bytes> {
  const base = await subtle.importKey("raw", utf8Encode(passphrase.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
  const params = { name: "PBKDF2", hash: "SHA-256", salt, iterations } as DeriveParams;
  return new Uint8Array(await subtle.deriveBits(params, base, 256));
}

export async function seal(key: CryptoKey, plaintext: Bytes, additionalData: string): Promise<{ iv: Bytes; ct: Bytes }> {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8Encode(additionalData), tagLength: 128 },
    key,
    plaintext,
  );
  return { iv, ct: new Uint8Array(ct) };
}

export async function unseal(key: CryptoKey, iv: Bytes, ct: Bytes, additionalData: string): Promise<Bytes> {
  const plain = await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: utf8Encode(additionalData), tagLength: 128 },
    key,
    ct,
  );
  return new Uint8Array(plain);
}

// ---- Payloads --------------------------------------------------------------

function assertPayload(value: unknown): asserts value is Payload {
  const p = value as Partial<Payload> | null;
  if (typeof p !== "object" || p === null || p.v !== 1 || typeof p.text !== "string") {
    throw new TypeError("Invalid payload");
  }
  if (p.file === null) return;
  const f = p.file as Partial<NonNullable<Payload["file"]>> | undefined;
  if (
    typeof f !== "object" ||
    f === null ||
    typeof f.name !== "string" ||
    typeof f.type !== "string" ||
    !Number.isSafeInteger(f.size) ||
    (f.size as number) < 1
  ) {
    throw new TypeError("Invalid payload");
  }
}

export async function sealPayload(key: CryptoKey, additionalData: string, payload: Payload): Promise<Sealed> {
  assertPayload(payload);
  const canonical: Payload = { v: 1, text: payload.text, file: payload.file };
  const json = utf8Encode(JSON.stringify(canonical));
  if (json.length > LIMITS.payloadMaxBytes) throw new RangeError("Payload too large");
  const { iv, ct } = await seal(key, frame(json), additionalData);
  return { iv: b64urlEncode(iv), ct: b64urlEncode(ct) };
}

export async function openPayload(key: CryptoKey, additionalData: string, sealed: Sealed): Promise<Payload> {
  const framed = await unseal(key, b64urlDecode(sealed.iv), b64urlDecode(sealed.ct), additionalData);
  const value: unknown = JSON.parse(utf8Decode(unframe(framed)));
  assertPayload(value);
  const file = value.file && { name: value.file.name, type: value.file.type, size: value.file.size };
  return { v: 1, text: value.text, file };
}

/** Padded plaintext length of a file: Padmé, but never below 1 KiB, as for text. */
export function filePaddedLength(size: number): number {
  return Math.max(LIMITS.minFrameBytes, padme(size));
}

export async function sealFile(key: CryptoKey, additionalData: string, data: Bytes): Promise<{ iv: string; ct: Bytes }> {
  if (data.length < 1 || data.length > LIMITS.fileMaxBytes) throw new RangeError("Invalid file size");
  const padded = new Uint8Array(filePaddedLength(data.length));
  padded.set(data);
  const { iv, ct } = await seal(key, padded, additionalData);
  return { iv: b64urlEncode(iv), ct };
}

export async function openFile(key: CryptoKey, additionalData: string, iv: string, ct: Bytes, size: number): Promise<Bytes> {
  const padded = await unseal(key, b64urlDecode(iv), ct, additionalData);
  // padme(size) alone is the format of files sealed before the 1 KiB floor.
  if (!Number.isSafeInteger(size) || size < 1 || (filePaddedLength(size) !== padded.length && padme(size) !== padded.length)) {
    throw new Error("Invalid file size");
  }
  return padded.subarray(0, size);
}

/** Additional authenticated data: binds every ciphertext to its purpose and record. */
export const aad = {
  secretText: (id: string) => `${PROTOCOL}/secret/text/${id}`,
  secretFile: (id: string) => `${PROTOCOL}/secret/file/${id}`,
  requestNote: (id: string) => `${PROTOCOL}/request/note/${id}`,
  requestText: (id: string) => `${PROTOCOL}/request/text/${id}`,
  requestFile: (id: string) => `${PROTOCOL}/request/file/${id}`,
};

function assertKey(key: Bytes): void {
  if (key.length !== KEY_BYTES) throw new RangeError("Invalid key length");
}

/**
 * A record id the server can check: the first 16 bytes of SHA-256 over a label and the
 * record's first capability hash (metaHash or submitHash). Someone who only knows an id
 * cannot find a matching hash, so they cannot create a record under it to learn whether
 * that id is in use.
 */
export async function boundId(kind: "secret" | "request", capabilityHash: string): Promise<string> {
  const digest = await sha256(concatBytes(utf8Encode(`${PROTOCOL}/${kind}/bound-id`), b64urlDecode(capabilityHash)));
  return b64urlEncode(digest.subarray(0, 16));
}

// ---- Secrets ---------------------------------------------------------------

/**
 * Public address of a secret, derived from the link key S (never sent to the server).
 * `legacyId` is the id format of links created before ids were bound (see shared/legacy.ts).
 */
export async function secretAddress(S: Bytes): Promise<{ id: string; legacyId: string; metaToken: string }> {
  assertKey(S);
  const metaToken = b64urlEncode(await hkdfBits(S, `${PROTOCOL}/secret/meta`, 256));
  return {
    id: await boundId("secret", await tokenHash(metaToken)),
    legacyId: b64urlEncode(await hkdfBits(S, `${PROTOCOL}/secret/id`, 128)),
    metaToken,
  };
}

export interface SecretKeys {
  readToken: string;
  textKey: CryptoKey;
  fileKey: CryptoKey;
}

export function assertKdf(kdf: KdfParams): void {
  if (
    kdf.alg !== "PBKDF2-SHA256" ||
    !Number.isSafeInteger(kdf.iterations) ||
    kdf.iterations < LIMITS.pbkdf2MinIterations ||
    kdf.iterations > LIMITS.pbkdf2MaxIterations ||
    !isB64url(kdf.salt, 16)
  ) {
    throw new RangeError("Unsupported passphrase parameters");
  }
}

/**
 * Keys for a secret. With a passphrase, the PBKDF2 output is mixed into the
 * key material, so the passphrase is real encryption and never leaves the browser.
 */
export async function secretKeys(
  S: Bytes,
  passphrase: { passphrase: string; kdf: KdfParams } | null,
): Promise<SecretKeys> {
  assertKey(S);
  let ikm = S;
  if (passphrase) {
    const { kdf } = passphrase;
    if (kdf.alg !== "PBKDF2-SHA256") throw new RangeError("Unsupported passphrase parameters");
    ikm = concatBytes(S, await passphraseBits(passphrase.passphrase, b64urlDecode(kdf.salt), kdf.iterations));
  }
  return {
    readToken: b64urlEncode(await hkdfBits(ikm, `${PROTOCOL}/secret/read`, 256)),
    textKey: await hkdfAesKey(ikm, `${PROTOCOL}/secret/text`),
    fileKey: await hkdfAesKey(ikm, `${PROTOCOL}/secret/file`),
  };
}

// ---- Requests (public-key, so only the requester can read submissions) ----

export async function newRequester(): Promise<{ Q: Bytes; pub: Bytes; d: Bytes }> {
  const pair = (await subtle.generateKey(P256, true, ["deriveBits"])) as CryptoKeyPair;
  const pub = new Uint8Array((await subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  const jwk = (await subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  if (typeof jwk.d !== "string") throw new Error("Key export failed");
  return { Q: randomBytes(KEY_BYTES), pub, d: b64urlDecode(jwk.d) };
}

export async function requestAddress(
  Q: Bytes,
): Promise<{ id: string; legacyId: string; submitToken: string; noteKey: CryptoKey }> {
  assertKey(Q);
  const submitToken = b64urlEncode(await hkdfBits(Q, `${PROTOCOL}/request/submit`, 256));
  return {
    id: await boundId("request", await tokenHash(submitToken)),
    legacyId: b64urlEncode(await hkdfBits(Q, `${PROTOCOL}/request/id`, 128)),
    submitToken,
    noteKey: await hkdfAesKey(Q, `${PROTOCOL}/request/note`),
  };
}

/** Inbox capability: needs both Q and the private key, so the client link cannot derive it. */
export async function inboxToken(Q: Bytes, d: Bytes): Promise<string> {
  assertKey(Q);
  assertKey(d);
  return b64urlEncode(await hkdfBits(concatBytes(Q, d), `${PROTOCOL}/request/inbox`, 256));
}

async function contentKeys(Z: Bytes, Q: Bytes, id: string, ephPub: Bytes) {
  // Mixing Q in means a server compromise plus a future break of ECDH still
  // cannot decrypt without one of the links.
  const ikm = concatBytes(Z, Q);
  const context = `${id}/${b64urlEncode(ephPub)}`;
  return {
    textKey: await hkdfAesKey(ikm, `${PROTOCOL}/request/text/${context}`),
    fileKey: await hkdfAesKey(ikm, `${PROTOCOL}/request/file/${context}`),
  };
}

function ecdh(peer: CryptoKey): DeriveParams {
  return { name: "ECDH", public: peer } as unknown as DeriveParams;
}

/** Sender side: ephemeral ECDH P-256 against the requester's public key. */
export async function senderKeys(requesterPub: Bytes, Q: Bytes, id: string) {
  assertKey(Q);
  const peer = await subtle.importKey("raw", requesterPub, P256, false, []);
  const eph = (await subtle.generateKey(P256, false, ["deriveBits"])) as CryptoKeyPair;
  const ephPub = new Uint8Array((await subtle.exportKey("raw", eph.publicKey)) as ArrayBuffer);
  const Z = new Uint8Array(await subtle.deriveBits(ecdh(peer), eph.privateKey, 256));
  return { ephPub, ...(await contentKeys(Z, Q, id, ephPub)) };
}

/** Requester side: recompute the shared secret with the private key from the inbox link. */
export async function requesterKeys(pub: Bytes, d: Bytes, Q: Bytes, id: string, ephPub: Bytes) {
  assertKey(Q);
  assertKey(d);
  if (pub.length !== 65 || pub[0] !== 4) throw new RangeError("Invalid public key");
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: b64urlEncode(pub.subarray(1, 33)),
    y: b64urlEncode(pub.subarray(33, 65)),
    d: b64urlEncode(d),
    ext: false,
  };
  const priv = await subtle.importKey("jwk", jwk, P256, false, ["deriveBits"]);
  const peer = await subtle.importKey("raw", ephPub, P256, false, []);
  const Z = new Uint8Array(await subtle.deriveBits(ecdh(peer), priv, 256));
  return contentKeys(Z, Q, id, ephPub);
}

// ---- Passphrases -----------------------------------------------------------

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** 100-bit passphrase in unambiguous Crockford base32, e.g. "7KQ2-MX9P-4TRW-HC3D-Y8NB". */
export function generatePassphrase(groups = 5, size = 4): string {
  const bytes = randomBytes(groups * size);
  const chars = Array.from(bytes, (b) => CROCKFORD.charAt(b & 31)).join("");
  return Array.from({ length: groups }, (_, i) => chars.slice(i * size, (i + 1) * size)).join("-");
}
