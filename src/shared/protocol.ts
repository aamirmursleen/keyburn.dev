// Protocol constants, limits and API shapes shared by the client and the Worker.

export const PROTOCOL = "osss/v1";

export const SECRET_EXPIRY_SECONDS = [900, 3600, 86400, 259200, 604800] as const;
export const REQUEST_EXPIRY_SECONDS = [3600, 86400, 259200, 604800] as const;
export const VIEW_CHOICES = [1, 2, 3, 5, 10] as const;

export const LIMITS = {
  /** Max UTF-8 size of an encrypted payload's JSON (text + file metadata). */
  payloadMaxBytes: 64 * 1024,
  /** Every text payload is padded to at least this many bytes. */
  minFrameBytes: 1024,
  /** Max plaintext file size. */
  fileMaxBytes: 25 * 1024 * 1024,
  fileNameMaxChars: 200,
  noteMaxChars: 1000,
  noteMaxFrameBytes: 8192,
  passphraseAttempts: 5,
  pbkdf2MinIterations: 600_000,
  pbkdf2MaxIterations: 5_000_000,
  jsonBodyMaxBytes: 256 * 1024,
  uploadWindowMs: 15 * 60 * 1000,
  downloadTicketMs: 15 * 60 * 1000,
  submissionRetentionMs: 7 * 24 * 60 * 60 * 1000,
  tombstoneRetentionMs: 30 * 24 * 60 * 60 * 1000,
} as const;

/** AES-GCM tag length in bytes. */
export const GCM_TAG_BYTES = 16;

export type ApiResult<T> = { success: true; data: T } | { success: false; error: ApiError; attemptsLeft?: number };

export type ApiError =
  | "bad_request"
  | "unsupported_media_type"
  | "payload_too_large"
  | "forbidden"
  | "method_not_allowed"
  | "not_found"
  | "conflict"
  | "wrong_passphrase"
  | "rate_limited"
  | "quota_exceeded"
  | "capacity"
  | "unavailable"
  | "internal";

export interface KdfParams {
  alg: "PBKDF2-SHA256";
  iterations: number;
  salt: string;
}

export interface Sealed {
  iv: string;
  ct: string;
}

export interface FileDeclaration {
  /** Ciphertext size in bytes (padded plaintext + GCM tag). */
  size: number;
  iv: string;
}

export interface FileTicket {
  size: number;
  iv: string;
  ticket: string;
}

/** Why a secret or request no longer has content. */
export type GoneReason = "viewed" | "expired" | "revoked" | "locked" | "opened" | "abandoned";

export interface ViewEvent {
  at: number;
  country: string | null;
}

// ---- Secrets ---------------------------------------------------------------

export interface CreateSecretInput {
  id: string;
  metaHash: string;
  readHash: string;
  manageHash: string;
  iv: string;
  ct: string;
  expiresIn: number;
  maxViews: number;
  kdf: KdfParams | null;
  file: FileDeclaration | null;
}

export interface CreateSecretOutput {
  expiresAt: number;
  uploadToken: string | null;
}

export type SecretMetaOutput =
  | {
      state: "active";
      kdf: KdfParams | null;
      expiresAt: number;
      viewsLeft: number;
      attemptsLeft: number;
      file: { size: number } | null;
    }
  | { state: "gone"; reason: GoneReason; at: number };

export interface OpenSecretOutput {
  iv: string;
  ct: string;
  viewsLeft: number;
  file: FileTicket | null;
}

export type SecretStatusOutput = {
  state: "active" | GoneReason;
  createdAt: number;
  expiresAt: number;
  endedAt: number | null;
  maxViews: number;
  viewsLeft: number;
  passphrase: boolean;
  hasFile: boolean;
  views: ViewEvent[];
};

// ---- Requests --------------------------------------------------------------

export interface CreateRequestInput {
  id: string;
  submitHash: string;
  inboxHash: string;
  pub: string;
  note: Sealed | null;
  expiresIn: number;
}

export interface CreateRequestOutput {
  expiresAt: number;
}

export type RequestInfoOutput =
  | { state: "open"; note: Sealed | null; expiresAt: number }
  | { state: "closed"; reason: "submitted" | GoneReason };

export interface SubmitRequestInput {
  id: string;
  submitToken: string;
  ephPub: string;
  iv: string;
  ct: string;
  file: FileDeclaration | null;
}

export interface SubmitRequestOutput {
  uploadToken: string | null;
}

export type InboxState = "waiting" | "receiving" | "received" | GoneReason;

export interface InboxStatusOutput {
  state: InboxState;
  createdAt: number;
  expiresAt: number;
  endedAt: number | null;
  pub: string | null;
  note: Sealed | null;
  submittedAt: number | null;
  country: string | null;
  file: { size: number } | null;
}

export interface OpenInboxOutput {
  ephPub: string;
  iv: string;
  ct: string;
  file: FileTicket | null;
}

/** Encrypted payload format (the plaintext inside every text ciphertext). */
export interface Payload {
  v: 1;
  text: string;
  file: { name: string; type: string; size: number } | null;
}
