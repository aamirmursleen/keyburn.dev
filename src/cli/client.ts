import {
  aad,
  assertKdf,
  generatePassphrase,
  openFile,
  openPayload,
  randomBytes,
  sealFile,
  sealPayload,
  secretAddress,
  secretKeys,
  tokenHash,
} from "../shared/crypto";
import { b64urlEncode, isB64url, type Bytes } from "../shared/encoding";
import { lookupWithLegacyId } from "../shared/legacy";
import { safeFileName } from "../shared/names";
import {
  GCM_TAG_BYTES,
  LIMITS,
  SECRET_EXPIRY_SECONDS,
  VIEW_CHOICES,
  type CreateSecretInput,
  type CreateSecretOutput,
  type KdfParams,
  type OpenSecretOutput,
  type SecretStatusOutput,
} from "../shared/protocol";
import { CliError } from "./errors";
import type { Api, Outcome } from "./http";
import { links, type ReceiptLink } from "./links";

// ---- strict checks on everything the server returns -------------------------

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isInt = (v: unknown, min: number, max: number): v is number => Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max;
const isTime = (v: unknown): v is number => isInt(v, 0, 8_640_000_000_000_000);
const MAX_FILE_CT = LIMITS.fileMaxBytes + GCM_TAG_BYTES;
const GONE = new Set(["viewed", "expired", "revoked", "locked", "opened", "abandoned"]);

function invalidResponse(): never {
  throw new CliError("server", "The server sent an unexpected response.");
}

function checkKdf(v: unknown): KdfParams | null {
  if (v === null) return null;
  if (!isObj(v) || v.alg !== "PBKDF2-SHA256" || !isInt(v.iterations, LIMITS.pbkdf2MinIterations, LIMITS.pbkdf2MaxIterations) || !isB64url(v.salt, 16)) {
    invalidResponse();
  }
  const kdf: KdfParams = { alg: "PBKDF2-SHA256", iterations: v.iterations as number, salt: v.salt as string };
  assertKdf(kdf);
  return kdf;
}

type Meta = { kdf: KdfParams | null; expiresAt: number; viewsLeft: number };

function checkMeta(v: unknown): Meta {
  if (!isObj(v)) invalidResponse();
  if (v.state === "gone") {
    const reason = typeof v.reason === "string" && GONE.has(v.reason) ? v.reason : "deleted";
    throw new CliError("gone", `This secret is no longer available (${reason}).`);
  }
  if (v.state !== "active" || !isTime(v.expiresAt) || !isInt(v.viewsLeft, 1, 10)) invalidResponse();
  return { kdf: checkKdf(v.kdf), expiresAt: v.expiresAt, viewsLeft: v.viewsLeft };
}

function checkOpened(v: unknown): OpenSecretOutput {
  if (!isObj(v) || !isB64url(v.iv, 12) || typeof v.ct !== "string" || v.ct.length > 200_000 || !isInt(v.viewsLeft, 0, 10)) {
    invalidResponse();
  }
  let file: OpenSecretOutput["file"] = null;
  if (v.file !== null) {
    const f = v.file;
    if (!isObj(f) || !isInt(f.size, GCM_TAG_BYTES + 1, MAX_FILE_CT) || !isB64url(f.iv, 12) || !isB64url(f.ticket, 32)) {
      invalidResponse();
    }
    file = { size: f.size as number, iv: f.iv as string, ticket: f.ticket as string };
  }
  return { iv: v.iv as string, ct: v.ct, viewsLeft: v.viewsLeft, file };
}

function apiFailure(outcome: Exclude<Outcome<unknown>, { ok: true }>): never {
  switch (outcome.error) {
    case "not_found":
      throw new CliError("not_found", "This secret doesn't exist (the link is wrong, or it was already used or deleted).");
    case "rate_limited":
    case "quota_exceeded":
    case "capacity":
      throw new CliError("rate_limited", "The service is limiting requests right now. Try again later.");
    case "payload_too_large":
      throw new CliError("too_large", "That's too large: text can be up to 64 KB and files up to 25 MB.");
    case "network":
      throw new CliError("network", "Couldn't reach the server.");
    default:
      throw new CliError("server", `The server refused the request (${outcome.error}).`);
  }
}

// ---- open --------------------------------------------------------------------

export interface OpenedSecret {
  text: string;
  file: { name: string; type: string; data: Bytes } | null;
  viewsLeft: number;
  expiresAt: number;
}

/**
 * Opens a secret link locally. Checks first whether a passphrase is needed, so a missing
 * passphrase never uses up a view or an attempt. Never retries: an open uses a view.
 */
export async function openSecret(api: Api, S: Bytes, passphrase: string | null): Promise<OpenedSecret> {
  const address = await secretAddress(S);
  const { metaToken } = address;
  const { id, res } = await lookupWithLegacyId(address, (id) => api.post<unknown>("secret/meta", { id, metaToken }));
  if (!res.ok) apiFailure(res);
  const meta = checkMeta(res.data);
  if (meta.kdf && passphrase === null) {
    throw new CliError("passphrase_required", "This secret is protected by a passphrase.");
  }

  const keys = await secretKeys(S, meta.kdf && passphrase !== null ? { passphrase, kdf: meta.kdf } : null);
  const opened = await api.post<unknown>("secret/open", { id, metaToken, readToken: keys.readToken });
  if (!opened.ok) {
    if (opened.error === "wrong_passphrase") {
      const left = opened.attemptsLeft ?? 0;
      throw new CliError(
        "wrong_passphrase",
        left > 0 ? `Wrong passphrase. ${left} attempt(s) left before the secret is destroyed.` : "Wrong passphrase. The secret has been destroyed.",
        left,
      );
    }
    apiFailure(opened);
  }
  const data = checkOpened(opened.data);

  let payload;
  try {
    payload = await openPayload(keys.textKey, aad.secretText(id), data);
  } catch {
    throw new CliError("server", "This secret couldn't be decrypted. The link may be damaged or the data altered.");
  }

  let file: OpenedSecret["file"] = null;
  if (payload.file && data.file) {
    // The size was already capped by checkOpened; openFile re-checks the padded layout.
    const download = await api.download("secret", id, data.file.ticket, data.file.size);
    if (!download.ok) apiFailure(download);
    try {
      const bytes = await openFile(keys.fileKey, aad.secretFile(id), data.file.iv, download.data, payload.file.size);
      file = { name: payload.file.name, type: payload.file.type, data: bytes };
    } catch {
      throw new CliError("server", "The attached file couldn't be decrypted. It may have been altered.");
    }
  }
  return { text: payload.text, file, viewsLeft: data.viewsLeft, expiresAt: meta.expiresAt };
}

// ---- share -------------------------------------------------------------------

export interface ShareInput {
  text: string;
  file: { name: string; type: string; data: Bytes } | null;
  views: (typeof VIEW_CHOICES)[number];
  expiresIn: (typeof SECRET_EXPIRY_SECONDS)[number];
  /** true generates a passphrase; a string uses that one; null for none. */
  passphrase: string | boolean | null;
}

export interface Shared {
  link: string;
  receipt: string;
  passphrase: string | null;
  expiresAt: number;
}

/** Encrypts locally exactly like the browser does and creates the secret. */
export async function shareSecret(api: Api, input: ShareInput): Promise<Shared> {
  if (input.file && (input.file.data.length < 1 || input.file.data.length > LIMITS.fileMaxBytes)) {
    throw new CliError("too_large", "Files must be between 1 byte and 25 MB.");
  }
  const passphrase = input.passphrase === true ? generatePassphrase() : typeof input.passphrase === "string" ? input.passphrase : null;
  const S = randomBytes(32);
  const { id, metaToken } = await secretAddress(S);
  const kdf: KdfParams | null = passphrase
    ? { alg: "PBKDF2-SHA256", iterations: LIMITS.pbkdf2MinIterations, salt: b64urlEncode(randomBytes(16)) }
    : null;
  const keys = await secretKeys(S, kdf && passphrase ? { passphrase, kdf } : null);
  const fileMeta = input.file
    ? { name: safeFileName(input.file.name), type: input.file.type || "application/octet-stream", size: input.file.data.length }
    : null;
  let sealed;
  try {
    sealed = await sealPayload(keys.textKey, aad.secretText(id), { v: 1, text: input.text, file: fileMeta });
  } catch (error) {
    if (error instanceof RangeError) throw new CliError("too_large", "That text is too long (the limit is 64 KB). Attach it as a file instead.");
    throw error;
  }
  const sealedFile = input.file ? await sealFile(keys.fileKey, aad.secretFile(id), input.file.data) : null;
  const manageToken = b64urlEncode(randomBytes(32));
  const body: CreateSecretInput = {
    id,
    metaHash: await tokenHash(metaToken),
    readHash: await tokenHash(keys.readToken),
    manageHash: await tokenHash(manageToken),
    iv: sealed.iv,
    ct: sealed.ct,
    expiresIn: input.expiresIn,
    maxViews: input.views,
    kdf,
    file: sealedFile ? { size: sealedFile.ct.length, iv: sealedFile.iv } : null,
  };
  const created = await api.post<CreateSecretOutput>("secret/create", body);
  if (!created.ok) apiFailure(created);
  if (!isObj(created.data) || !isTime(created.data.expiresAt)) invalidResponse();
  if (sealedFile) {
    const token = created.data.uploadToken;
    if (!isB64url(token, 32)) invalidResponse();
    const uploaded = await api.upload("secret", id, token, sealedFile.ct);
    if (!uploaded.ok) apiFailure(uploaded);
  }
  return {
    link: links.secret(api.origin, S),
    receipt: links.receipt(api.origin, id, manageToken),
    passphrase,
    expiresAt: created.data.expiresAt,
  };
}

// ---- receipts ----------------------------------------------------------------

export interface Receipt {
  state: string;
  createdAt: number;
  expiresAt: number;
  endedAt: number | null;
  maxViews: number;
  viewsLeft: number;
  views: { at: number; country: string | null }[];
}

function checkStatus(v: unknown): Receipt {
  const states = new Set(["active", ...GONE]);
  if (
    !isObj(v) ||
    typeof v.state !== "string" ||
    !states.has(v.state) ||
    !isTime(v.createdAt) ||
    !isTime(v.expiresAt) ||
    !(v.endedAt === null || isTime(v.endedAt)) ||
    !isInt(v.maxViews, 1, 10) ||
    !isInt(v.viewsLeft, 0, 10) ||
    !Array.isArray(v.views) ||
    v.views.length > 10
  ) {
    invalidResponse();
  }
  const views = (v.views as unknown[]).map((e) => {
    if (!isObj(e) || !isTime(e.at) || !(e.country === null || (typeof e.country === "string" && /^[A-Z0-9]{2}$/.test(e.country)))) {
      invalidResponse();
    }
    return { at: e.at as number, country: e.country as string | null };
  });
  return {
    state: v.state,
    createdAt: v.createdAt,
    expiresAt: v.expiresAt,
    endedAt: v.endedAt as number | null,
    maxViews: v.maxViews,
    viewsLeft: v.viewsLeft,
    views,
  };
}

export async function secretStatus(api: Api, receipt: ReceiptLink): Promise<Receipt> {
  const res = await api.post<SecretStatusOutput>("secret/status", { id: receipt.id, manageToken: receipt.manageToken });
  if (!res.ok) apiFailure(res);
  return checkStatus(res.data);
}

export async function revokeSecret(api: Api, receipt: ReceiptLink): Promise<Receipt> {
  const res = await api.post<SecretStatusOutput>("secret/revoke", { id: receipt.id, manageToken: receipt.manageToken });
  if (!res.ok) apiFailure(res);
  return checkStatus(res.data);
}
