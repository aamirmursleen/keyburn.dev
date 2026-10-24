// Byte/string helpers shared by the browser client and the Worker.
// Everything here is dependency-free and works in any WebCrypto runtime.

export type Bytes = Uint8Array<ArrayBuffer>;

const B64URL_CHARS = /^[A-Za-z0-9_-]*$/;
const CHUNK = 0x8000;

export function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url decoder: rejects padding, foreign characters and non-canonical input. */
export function b64urlDecode(value: string): Bytes {
  if (!B64URL_CHARS.test(value) || value.length % 4 === 1) {
    throw new TypeError("Invalid base64url");
  }
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  if (b64urlEncode(out) !== value) throw new TypeError("Non-canonical base64url");
  return out;
}

/** True when `value` is canonical base64url that decodes to exactly `byteLength` bytes. */
export function isB64url(value: unknown, byteLength: number): value is string {
  if (typeof value !== "string" || value.length !== Math.ceil((byteLength * 4) / 3)) return false;
  try {
    return b64urlDecode(value).length === byteLength;
  } catch {
    return false;
  }
}

const encoder = new TextEncoder();

export function utf8Encode(text: string): Bytes {
  // TextEncoder always returns an ArrayBuffer-backed array.
  return encoder.encode(text) as Bytes;
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
}

export function concatBytes(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
