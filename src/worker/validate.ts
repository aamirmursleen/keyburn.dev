// Strict, dependency-free validation of untrusted API input. Every object
// must have exactly the expected keys; every binary field must be canonical
// base64url of the exact size; every ciphertext must be Padmé-padded.

import { padme } from "../shared/crypto";
import { b64urlDecode, isB64url } from "../shared/encoding";
import {
  GCM_TAG_BYTES,
  LIMITS,
  REQUEST_EXPIRY_SECONDS,
  SECRET_EXPIRY_SECONDS,
  VIEW_CHOICES,
  type CreateRequestInput,
  type CreateSecretInput,
  type FileDeclaration,
  type KdfParams,
  type Sealed,
  type SubmitRequestInput,
} from "../shared/protocol";
import { HttpError } from "./http";

const B64URL = /^[A-Za-z0-9_-]+$/;
const TEXT_FRAME_MAX = padme(LIMITS.payloadMaxBytes + 4);

function invalid(): never {
  throw new HttpError(400, "bad_request");
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  const record = value as Record<string, unknown>;
  const present = Object.keys(record);
  if (present.length !== keys.length || !keys.every((key) => Object.hasOwn(record, key))) invalid();
  return record;
}

function bytes(value: unknown, length: number): string {
  if (!isB64url(value, length)) invalid();
  return value;
}

export const isId = (value: unknown): value is string => isB64url(value, 16);
const id = (value: unknown): string => bytes(value, 16);
const token = (value: unknown): string => bytes(value, 32);
const iv = (value: unknown): string => bytes(value, 12);

/** Decoded size of a base64url string, computed without decoding it. */
export function encodedSize(value: string): number {
  return Math.floor((value.length * 3) / 4);
}

function sealedFrame(value: unknown, maxFrame: number): string {
  if (
    typeof value !== "string" ||
    value.length % 4 === 1 ||
    value.length > Math.ceil(((maxFrame + GCM_TAG_BYTES) * 4) / 3) ||
    !B64URL.test(value)
  ) {
    invalid();
  }
  const frame = encodedSize(value) - GCM_TAG_BYTES;
  if (frame < LIMITS.minFrameBytes || frame > maxFrame || padme(frame) !== frame) invalid();
  // Canonical encoding too, so a reader's strict decoder never fails after a view is spent.
  if (!isB64url(value, frame + GCM_TAG_BYTES)) invalid();
  return value;
}

function oneOf<T extends number>(value: unknown, choices: readonly T[]): T {
  if (!choices.includes(value as T)) invalid();
  return value as T;
}

function kdf(value: unknown): KdfParams | null {
  if (value === null) return null;
  const o = exact(value, ["alg", "iterations", "salt"]);
  const iterations = o.iterations;
  if (
    o.alg !== "PBKDF2-SHA256" ||
    !Number.isSafeInteger(iterations) ||
    (iterations as number) < LIMITS.pbkdf2MinIterations ||
    (iterations as number) > LIMITS.pbkdf2MaxIterations
  ) {
    invalid();
  }
  return { alg: "PBKDF2-SHA256", iterations: iterations as number, salt: bytes(o.salt, 16) };
}

function file(value: unknown): FileDeclaration | null {
  if (value === null) return null;
  const o = exact(value, ["size", "iv"]);
  if (!Number.isSafeInteger(o.size)) invalid();
  const padded = (o.size as number) - GCM_TAG_BYTES;
  if (padded < LIMITS.minFrameBytes || padded > LIMITS.fileMaxBytes || padme(padded) !== padded) invalid();
  return { size: o.size as number, iv: iv(o.iv) };
}

function note(value: unknown): Sealed | null {
  if (value === null) return null;
  const o = exact(value, ["iv", "ct"]);
  return { iv: iv(o.iv), ct: sealedFrame(o.ct, LIMITS.noteMaxFrameBytes) };
}

function publicKey(value: unknown): string {
  const key = bytes(value, 65);
  if (b64urlDecode(key)[0] !== 4) invalid(); // uncompressed P-256 point
  return key;
}

export function parseCreateSecret(body: unknown): CreateSecretInput {
  const o = exact(body, ["id", "metaHash", "readHash", "manageHash", "iv", "ct", "expiresIn", "maxViews", "kdf", "file"]);
  return {
    id: id(o.id),
    metaHash: token(o.metaHash),
    readHash: token(o.readHash),
    manageHash: token(o.manageHash),
    iv: iv(o.iv),
    ct: sealedFrame(o.ct, TEXT_FRAME_MAX),
    expiresIn: oneOf(o.expiresIn, SECRET_EXPIRY_SECONDS),
    maxViews: oneOf(o.maxViews, VIEW_CHOICES),
    kdf: kdf(o.kdf),
    file: file(o.file),
  };
}

/** `{ id, <tokenName> }` bodies used by most read and manage endpoints. */
export function parseIdToken<K extends string>(body: unknown, tokenName: K): { id: string } & Record<K, string> {
  const o = exact(body, ["id", tokenName]);
  return { id: id(o.id), [tokenName]: token(o[tokenName]) } as { id: string } & Record<K, string>;
}

export function parseOpenSecret(body: unknown): { id: string; metaToken: string; readToken: string } {
  const o = exact(body, ["id", "metaToken", "readToken"]);
  return { id: id(o.id), metaToken: token(o.metaToken), readToken: token(o.readToken) };
}

export function parseCreateRequest(body: unknown): CreateRequestInput {
  const o = exact(body, ["id", "submitHash", "inboxHash", "pub", "note", "expiresIn"]);
  return {
    id: id(o.id),
    submitHash: token(o.submitHash),
    inboxHash: token(o.inboxHash),
    pub: publicKey(o.pub),
    note: note(o.note),
    expiresIn: oneOf(o.expiresIn, REQUEST_EXPIRY_SECONDS),
  };
}

export function parseSubmitRequest(body: unknown): SubmitRequestInput {
  const o = exact(body, ["id", "submitToken", "ephPub", "iv", "ct", "file"]);
  return {
    id: id(o.id),
    submitToken: token(o.submitToken),
    ephPub: publicKey(o.ephPub),
    iv: iv(o.iv),
    ct: sealedFrame(o.ct, TEXT_FRAME_MAX),
    file: file(o.file),
  };
}

export function parseUploadHeaders(headers: Headers): { kind: "secret" | "request"; id: string; token: string; length: number } {
  const box = /^(secret|request):([A-Za-z0-9_-]{22})$/.exec(headers.get("x-vault-box") ?? "");
  const auth = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(headers.get("authorization") ?? "");
  const length = Number(headers.get("content-length"));
  if (!box || !auth || !Number.isSafeInteger(length) || length <= 0) invalid();
  return { kind: box[1] as "secret" | "request", id: id(box[2]), token: token(auth[1]), length };
}
