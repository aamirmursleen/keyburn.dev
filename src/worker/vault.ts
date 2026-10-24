import { DurableObject } from "cloudflare:workers";
import { randomBytes, tokenHash } from "../shared/crypto";
import { b64urlEncode } from "../shared/encoding";
import {
  LIMITS,
  type ApiError,
  type CreateRequestInput,
  type CreateRequestOutput,
  type CreateSecretInput,
  type CreateSecretOutput,
  type FileDeclaration,
  type FileTicket,
  type GoneReason,
  type InboxState,
  type InboxStatusOutput,
  type KdfParams,
  type OpenInboxOutput,
  type OpenSecretOutput,
  type RequestInfoOutput,
  type Sealed,
  type SecretMetaOutput,
  type SecretStatusOutput,
  type SubmitRequestInput,
  type SubmitRequestOutput,
  type ViewEvent,
} from "../shared/protocol";
import { logError } from "./http";

// One Vault instance holds exactly one secret or one request. All state
// transitions below are synchronous: with no await between reading and
// writing, Durable Objects guarantee they are atomic, so a one-time secret
// can never be read twice and attempt counters cannot be raced.

export type VaultResult<T> = { ok: true; value: T } | { ok: false; error: ApiError; attemptsLeft?: number };

interface Ticket {
  hash: string;
  until: number;
  uses: number;
  done: boolean;
}

interface FileState {
  /** Key of the completed upload; null until an upload succeeds. */
  r2Key: string | null;
  /** In-flight upload attempts. Each writes to its own key, so retries can never clobber each other. */
  attempts: string[];
  /** Upload attempts started so far (absent on files declared before this was counted). */
  tries?: number;
  size: number;
  iv: string;
  ready: boolean;
  uploadHash: string | null;
  uploadUntil: number;
  tickets: Ticket[];
  /** Content was destroyed; the ciphertext lingers only for in-flight downloads. */
  draining: boolean;
}

interface SecretRecord {
  kind: "secret";
  createdAt: number;
  expiresAt: number;
  maxViews: number;
  viewsLeft: number;
  kdf: KdfParams | null;
  attemptsLeft: number;
  metaHash: string;
  readHash: string;
  manageHash: string;
  iv: string;
  ct: string;
  hasFile: boolean;
  views: ViewEvent[];
}

interface Submission {
  at: number;
  country: string | null;
  ephPub: string;
  iv: string;
  ct: string;
  hasFile: boolean;
  complete: boolean;
}

interface RequestRecord {
  kind: "request";
  createdAt: number;
  /** When the client link stops accepting a submission. */
  openUntil: number;
  /** When the record is destroyed (openUntil, or retention after a submission). */
  expiresAt: number;
  submitHash: string;
  inboxHash: string;
  pub: string;
  note: Sealed | null;
  submission: Submission | null;
}

type LiveRecord = SecretRecord | RequestRecord;

interface SecretTomb {
  kind: "secret";
  reason: GoneReason;
  at: number;
  purgeAt: number;
  createdAt: number;
  expiresAt: number;
  metaHash: string;
  manageHash: string;
  maxViews: number;
  viewsLeft: number;
  passphrase: boolean;
  hasFile: boolean;
  views: ViewEvent[];
}

interface RequestTomb {
  kind: "request";
  reason: GoneReason;
  at: number;
  purgeAt: number;
  createdAt: number;
  expiresAt: number;
  submitHash: string;
  inboxHash: string;
  note: Sealed | null;
  submittedAt: number | null;
  country: string | null;
}

type Tomb = SecretTomb | RequestTomb;

const MAX_TICKET_USES = 3;
const MAX_UPLOAD_ATTEMPTS = 5;
/** Total attempts per file, so failing uploads can't grow the deletion queue without bound. */
const MAX_UPLOAD_TRIES = 20;
/** Keys per R2 delete call, well under the platform's per-call limit. */
const R2_DELETE_BATCH = 100;
const RETRY_MS = 60_000;

const ok = <T>(value: T): VaultResult<T> => ({ ok: true, value });
const fail = <T>(error: ApiError, attemptsLeft?: number): VaultResult<T> =>
  attemptsLeft === undefined ? { ok: false, error } : { ok: false, error, attemptsLeft };

function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const encoder = new TextEncoder();
  return crypto.subtle.timingSafeEqual(encoder.encode(a), encoder.encode(b));
}

function newToken(): string {
  return b64urlEncode(randomBytes(32));
}

function newR2Key(): string {
  return `v1/${b64urlEncode(randomBytes(18))}`;
}

function newFile(declared: FileDeclaration, uploadHash: string, now: number): FileState {
  return {
    r2Key: null,
    attempts: [],
    size: declared.size,
    iv: declared.iv,
    ready: false,
    uploadHash,
    uploadUntil: now + LIMITS.uploadWindowMs,
    tickets: [],
    draining: false,
  };
}

/** Tickets that may start another download attempt. */
const liveTickets = (file: FileState, now: number): Ticket[] =>
  file.tickets.filter((t) => !t.done && t.uses < MAX_TICKET_USES && t.until > now);

/** Tickets whose download may still be in progress (including a last attempt that used up the retries). */
const pendingTickets = (file: FileState, now: number): Ticket[] =>
  file.tickets.filter((t) => !t.done && t.until > now);

/**
 * Storage keys. `burned` is the permanent, content-free marker left after a purge;
 * `r2ver` counts deletion requests so a batch in flight can't swallow a re-queued key.
 */
type Key = "rec" | "file" | "tomb" | "r2del" | "r2ver" | "r2retry" | "burned";

export class Vault extends DurableObject<Env> {
  // ---- storage helpers (synchronous KV API) --------------------------------
  // Helpers are #private: Workers RPC can't dispatch them, so a VAULT stub exposes only
  // the capability-checked methods below.

  #get<T>(key: Key): T | undefined {
    return this.ctx.storage.kv.get<T>(key);
  }

  #put(key: Key, value: unknown): void {
    this.ctx.storage.kv.put(key, value);
  }

  #drop(key: Key): void {
    this.ctx.storage.kv.delete(key);
  }

  #queueDelete(...keys: (string | null)[]): void {
    const wanted = keys.filter((key): key is string => key !== null);
    if (wanted.length === 0) return;
    const pending = this.#get<string[]>("r2del") ?? [];
    const added = wanted.filter((key) => !pending.includes(key));
    if (added.length > 0) this.#put("r2del", [...pending, ...added]);
    this.#put("r2ver", (this.#get<number>("r2ver") ?? 0) + 1);
  }

  #dropFile(file: FileState): void {
    this.#queueDelete(file.r2Key, ...file.attempts);
    this.#drop("file");
  }

  // ---- state machine ---------------------------------------------------------

  /** Moves a live record to a tombstone that holds no content. */
  #destroy(rec: LiveRecord, reason: GoneReason, now: number, keepForDownloads: boolean): void {
    const purgeAt = now + LIMITS.tombstoneRetentionMs;
    const tomb: Tomb =
      rec.kind === "secret"
        ? {
            kind: "secret",
            reason,
            at: now,
            purgeAt,
            createdAt: rec.createdAt,
            expiresAt: rec.expiresAt,
            metaHash: rec.metaHash,
            manageHash: rec.manageHash,
            maxViews: rec.maxViews,
            viewsLeft: rec.viewsLeft,
            passphrase: rec.kdf !== null,
            hasFile: rec.hasFile,
            views: rec.views,
          }
        : {
            kind: "request",
            reason,
            at: now,
            purgeAt,
            createdAt: rec.createdAt,
            expiresAt: rec.expiresAt,
            submitHash: rec.submitHash,
            inboxHash: rec.inboxHash,
            note: rec.note,
            submittedAt: rec.submission?.at ?? null,
            country: rec.submission?.country ?? null,
          };
    this.#put("tomb", tomb);
    this.#drop("rec");

    const file = this.#get<FileState>("file");
    if (!file) return;
    if (keepForDownloads && file.ready && pendingTickets(file, now).length > 0) {
      this.#put("file", { ...file, draining: true, uploadHash: null });
    } else {
      this.#dropFile(file);
    }
  }

  /** Applies every time-based transition that is due. Synchronous by design. */
  #reconcile(now: number): void {
    const rec = this.#get<LiveRecord>("rec");
    if (rec && now >= rec.expiresAt) {
      this.#destroy(rec, "expired", now, false);
    } else if (rec) {
      const file = this.#get<FileState>("file");
      if (file && !file.ready && now >= file.uploadUntil) {
        if (rec.kind === "secret") {
          this.#destroy(rec, "abandoned", now, false);
        } else {
          // The submitter never finished uploading: reopen the request.
          this.#dropFile(file);
          const reopened: RequestRecord = { ...rec, submission: null, expiresAt: rec.openUntil };
          this.#put("rec", reopened);
          if (now >= rec.openUntil) this.#destroy(reopened, "expired", now, false);
        }
      }
    }

    const file = this.#get<FileState>("file");
    if (file?.ready) {
      const pending = pendingTickets(file, now);
      if (file.draining && pending.length === 0) this.#dropFile(file);
      else if (pending.length !== file.tickets.length) this.#put("file", { ...file, tickets: pending });
    }
  }

  /** Schedules the next alarm. Only touches storage, so it keeps the transition atomic. */
  async #schedule(now: number): Promise<void> {
    const times: number[] = [];
    const rec = this.#get<LiveRecord>("rec");
    if (rec) times.push(rec.expiresAt);
    const file = this.#get<FileState>("file");
    if (file && !file.ready) times.push(file.uploadUntil);
    // Every unfinished ticket, including one whose retries are used up: an interrupted
    // final download must not leave a draining file in R2 until the tombstone purge.
    if (file) times.push(...pendingTickets(file, now).map((t) => t.until));
    const tomb = this.#get<Tomb>("tomb");
    if (tomb) times.push(tomb.purgeAt);
    // Pending deletions run now, unless a failed batch asked to back off until later.
    if ((this.#get<string[]>("r2del") ?? []).length > 0) times.push(Math.max(now, this.#get<number>("r2retry") ?? 0));

    const current = await this.ctx.storage.getAlarm();
    if (times.length === 0) {
      if (current !== null) await this.ctx.storage.deleteAlarm();
      return;
    }
    const next = Math.min(...times);
    if (current !== next) await this.ctx.storage.setAlarm(next);
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    this.#reconcile(now);

    // One bounded batch per run; the next alarm (scheduled for now) takes the rest.
    const pending = (this.#get<string[]>("r2del") ?? []).slice(0, R2_DELETE_BATCH);
    if (pending.length > 0) {
      const version = this.#get<number>("r2ver");
      try {
        await this.env.FILES.delete(pending);
      } catch (error) {
        logError("vault:r2-delete", error);
        this.#put("r2retry", now + RETRY_MS);
        await this.ctx.storage.setAlarm(now + RETRY_MS);
        return;
      }
      this.#drop("r2retry");
      // A key queued again while the batch was in flight (e.g. an upload that landed
      // after the delete ran) stays queued, so the next alarm deletes it again.
      if (this.#get<number>("r2ver") === version) {
        const remaining = (this.#get<string[]>("r2del") ?? []).filter((key) => !pending.includes(key));
        if (remaining.length > 0) {
          this.#put("r2del", remaining);
        } else {
          this.#drop("r2del");
          this.#drop("r2ver");
        }
      }
    }

    const tomb = this.#get<Tomb>("tomb");
    const idle = !this.#get("rec") && !this.#get("file") && !this.#get("r2del");
    if (tomb && idle && now >= tomb.purgeAt) {
      // Keep only a permanent, content-free marker. Without it the id could be created
      // again, and anyone holding an old link could publish new content behind it.
      this.#drop("tomb");
      this.#put("burned", true);
    }
    await this.#schedule(now);
  }

  #has(key: Key): boolean {
    return this.#get(key) !== undefined;
  }

  /** An id is bound to its first creator for good, even after its tombstone is purged. */
  #taken(): boolean {
    return this.#has("rec") || this.#has("tomb") || this.#has("file") || this.#has("burned");
  }

  async #finish<T>(now: number, result: VaultResult<T>): Promise<VaultResult<T>> {
    await this.#schedule(now);
    return result;
  }

  // ---- secrets ---------------------------------------------------------------

  async createSecret(input: CreateSecretInput): Promise<VaultResult<CreateSecretOutput>> {
    const uploadToken = input.file ? newToken() : null;
    const uploadHash = uploadToken ? await tokenHash(uploadToken) : null;
    const now = Date.now();
    if (this.#taken()) return fail("conflict");

    const expiresAt = now + input.expiresIn * 1000;
    const rec: SecretRecord = {
      kind: "secret",
      createdAt: now,
      expiresAt,
      maxViews: input.maxViews,
      viewsLeft: input.maxViews,
      kdf: input.kdf,
      attemptsLeft: LIMITS.passphraseAttempts,
      metaHash: input.metaHash,
      readHash: input.readHash,
      manageHash: input.manageHash,
      iv: input.iv,
      ct: input.ct,
      hasFile: input.file !== null,
      views: [],
    };
    this.#put("rec", rec);
    if (input.file && uploadHash) this.#put("file", newFile(input.file, uploadHash, now));
    return this.#finish(now, ok({ expiresAt, uploadToken }));
  }

  /** A secret is only visible to recipients once its file (if any) is uploaded. */
  #openableSecret(metaHash: string): SecretRecord | null {
    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind !== "secret" || !same(rec.metaHash, metaHash)) return null;
    if (rec.hasFile && !this.#get<FileState>("file")?.ready) return null;
    return rec;
  }

  async secretMeta(metaHash: string): Promise<VaultResult<SecretMetaOutput>> {
    const now = Date.now();
    this.#reconcile(now);
    const rec = this.#openableSecret(metaHash);
    if (rec) {
      const file = this.#get<FileState>("file");
      return this.#finish(
        now,
        ok({
          state: "active",
          kdf: rec.kdf,
          expiresAt: rec.expiresAt,
          viewsLeft: rec.viewsLeft,
          attemptsLeft: rec.attemptsLeft,
          file: rec.hasFile && file ? { size: file.size } : null,
        }),
      );
    }
    const tomb = this.#get<Tomb>("tomb");
    if (tomb?.kind === "secret" && same(tomb.metaHash, metaHash)) {
      return this.#finish(now, ok({ state: "gone", reason: tomb.reason, at: tomb.at }));
    }
    return this.#finish(now, fail("not_found"));
  }

  async openSecret(metaHash: string, readHash: string, country: string | null): Promise<VaultResult<OpenSecretOutput>> {
    const ticket = newToken();
    const ticketHash = await tokenHash(ticket);
    const now = Date.now();
    this.#reconcile(now);

    const rec = this.#openableSecret(metaHash);
    if (!rec) return this.#finish(now, fail("not_found"));

    if (!same(rec.readHash, readHash)) {
      const attemptsLeft = rec.attemptsLeft - 1;
      if (attemptsLeft <= 0) this.#destroy({ ...rec, attemptsLeft: 0 }, "locked", now, false);
      else this.#put("rec", { ...rec, attemptsLeft });
      return this.#finish(now, fail("wrong_passphrase", Math.max(0, attemptsLeft)));
    }

    const viewsLeft = rec.viewsLeft - 1;
    const next: SecretRecord = { ...rec, viewsLeft, views: [...rec.views, { at: now, country }] };
    let fileTicket: FileTicket | null = null;
    const file = this.#get<FileState>("file");
    if (rec.hasFile && file?.ready) {
      const entry: Ticket = { hash: ticketHash, until: now + LIMITS.downloadTicketMs, uses: 0, done: false };
      this.#put("file", { ...file, tickets: [...file.tickets, entry] });
      fileTicket = { size: file.size, iv: file.iv, ticket };
    }
    if (viewsLeft <= 0) this.#destroy(next, "viewed", now, true);
    else this.#put("rec", next);
    return this.#finish(now, ok({ iv: rec.iv, ct: rec.ct, viewsLeft, file: fileTicket }));
  }

  #secretStatusOf(manageHash: string): VaultResult<SecretStatusOutput> {
    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind === "secret" && same(rec.manageHash, manageHash)) {
      return ok({
        state: "active",
        createdAt: rec.createdAt,
        expiresAt: rec.expiresAt,
        endedAt: null,
        maxViews: rec.maxViews,
        viewsLeft: rec.viewsLeft,
        passphrase: rec.kdf !== null,
        hasFile: rec.hasFile,
        views: rec.views,
      });
    }
    const tomb = this.#get<Tomb>("tomb");
    if (tomb?.kind === "secret" && same(tomb.manageHash, manageHash)) {
      return ok({
        state: tomb.reason,
        createdAt: tomb.createdAt,
        expiresAt: tomb.expiresAt,
        endedAt: tomb.at,
        maxViews: tomb.maxViews,
        viewsLeft: tomb.viewsLeft,
        passphrase: tomb.passphrase,
        hasFile: tomb.hasFile,
        views: tomb.views,
      });
    }
    return fail("not_found");
  }

  async secretStatus(manageHash: string): Promise<VaultResult<SecretStatusOutput>> {
    const now = Date.now();
    this.#reconcile(now);
    return this.#finish(now, this.#secretStatusOf(manageHash));
  }

  async revokeSecret(manageHash: string): Promise<VaultResult<SecretStatusOutput>> {
    const now = Date.now();
    this.#reconcile(now);
    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind === "secret" && same(rec.manageHash, manageHash)) {
      this.#destroy(rec, "revoked", now, false);
    } else {
      // Already viewed: also cut off any download still in flight.
      const tomb = this.#get<Tomb>("tomb");
      const file = this.#get<FileState>("file");
      if (tomb?.kind === "secret" && same(tomb.manageHash, manageHash) && file) this.#dropFile(file);
    }
    return this.#finish(now, this.#secretStatusOf(manageHash));
  }

  // ---- requests --------------------------------------------------------------

  async createRequest(input: CreateRequestInput): Promise<VaultResult<CreateRequestOutput>> {
    const now = Date.now();
    if (this.#taken()) return fail("conflict");
    const expiresAt = now + input.expiresIn * 1000;
    const rec: RequestRecord = {
      kind: "request",
      createdAt: now,
      openUntil: expiresAt,
      expiresAt,
      submitHash: input.submitHash,
      inboxHash: input.inboxHash,
      pub: input.pub,
      note: input.note,
      submission: null,
    };
    this.#put("rec", rec);
    return this.#finish(now, ok({ expiresAt }));
  }

  async requestInfo(submitHash: string): Promise<VaultResult<RequestInfoOutput>> {
    const now = Date.now();
    this.#reconcile(now);
    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind === "request" && same(rec.submitHash, submitHash)) {
      return this.#finish(
        now,
        rec.submission
          ? ok<RequestInfoOutput>({ state: "closed", reason: "submitted" })
          : ok<RequestInfoOutput>({ state: "open", note: rec.note, expiresAt: rec.openUntil }),
      );
    }
    const tomb = this.#get<Tomb>("tomb");
    if (tomb?.kind === "request" && same(tomb.submitHash, submitHash)) {
      const reason = tomb.reason === "opened" ? "submitted" : tomb.reason;
      return this.#finish(now, ok({ state: "closed", reason }));
    }
    return this.#finish(now, fail("not_found"));
  }

  async submitRequest(
    submitHash: string,
    input: Omit<SubmitRequestInput, "id" | "submitToken">,
    country: string | null,
  ): Promise<VaultResult<SubmitRequestOutput>> {
    const uploadToken = input.file ? newToken() : null;
    const uploadHash = uploadToken ? await tokenHash(uploadToken) : null;
    const now = Date.now();
    this.#reconcile(now);

    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind !== "request" || !same(rec.submitHash, submitHash)) return this.#finish(now, fail("not_found"));
    if (rec.submission) return this.#finish(now, fail("conflict"));

    const complete = input.file === null;
    this.#put("rec", {
      ...rec,
      expiresAt: Math.max(rec.expiresAt, now + LIMITS.submissionRetentionMs),
      submission: {
        at: now,
        country,
        ephPub: input.ephPub,
        iv: input.iv,
        ct: input.ct,
        hasFile: !complete,
        complete,
      },
    } satisfies RequestRecord);
    if (input.file && uploadHash) this.#put("file", newFile(input.file, uploadHash, now));
    return this.#finish(now, ok({ uploadToken }));
  }

  #inboxOf(inboxHash: string): VaultResult<InboxStatusOutput> {
    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind === "request" && same(rec.inboxHash, inboxHash)) {
      const s = rec.submission;
      const file = this.#get<FileState>("file");
      const state: InboxState = !s ? "waiting" : s.complete ? "received" : "receiving";
      return ok({
        state,
        createdAt: rec.createdAt,
        expiresAt: s ? rec.expiresAt : rec.openUntil,
        endedAt: null,
        pub: rec.pub,
        note: rec.note,
        submittedAt: s?.at ?? null,
        country: s?.country ?? null,
        file: s?.hasFile && file ? { size: file.size } : null,
      });
    }
    const tomb = this.#get<Tomb>("tomb");
    if (tomb?.kind === "request" && same(tomb.inboxHash, inboxHash)) {
      return ok({
        state: tomb.reason,
        createdAt: tomb.createdAt,
        expiresAt: tomb.expiresAt,
        endedAt: tomb.at,
        pub: null,
        note: tomb.note,
        submittedAt: tomb.submittedAt,
        country: tomb.country,
        file: null,
      });
    }
    return fail("not_found");
  }

  async inboxStatus(inboxHash: string): Promise<VaultResult<InboxStatusOutput>> {
    const now = Date.now();
    this.#reconcile(now);
    return this.#finish(now, this.#inboxOf(inboxHash));
  }

  async openInbox(inboxHash: string): Promise<VaultResult<OpenInboxOutput>> {
    const ticket = newToken();
    const ticketHash = await tokenHash(ticket);
    const now = Date.now();
    this.#reconcile(now);

    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind !== "request" || !same(rec.inboxHash, inboxHash)) return this.#finish(now, fail("not_found"));
    const s = rec.submission;
    if (!s?.complete) return this.#finish(now, fail("conflict"));

    let fileTicket: FileTicket | null = null;
    const file = this.#get<FileState>("file");
    if (s.hasFile && file?.ready) {
      const entry: Ticket = { hash: ticketHash, until: now + LIMITS.downloadTicketMs, uses: 0, done: false };
      this.#put("file", { ...file, tickets: [...file.tickets, entry] });
      fileTicket = { size: file.size, iv: file.iv, ticket };
    }
    this.#destroy(rec, "opened", now, true);
    return this.#finish(now, ok({ ephPub: s.ephPub, iv: s.iv, ct: s.ct, file: fileTicket }));
  }

  async revokeRequest(inboxHash: string): Promise<VaultResult<InboxStatusOutput>> {
    const now = Date.now();
    this.#reconcile(now);
    const rec = this.#get<LiveRecord>("rec");
    if (rec?.kind === "request" && same(rec.inboxHash, inboxHash)) {
      this.#destroy(rec, "revoked", now, false);
    } else {
      // Already opened: also cut off a download still in flight, as for secrets.
      const tomb = this.#get<Tomb>("tomb");
      const file = this.#get<FileState>("file");
      if (tomb?.kind === "request" && same(tomb.inboxHash, inboxHash) && file) this.#dropFile(file);
    }
    return this.#finish(now, this.#inboxOf(inboxHash));
  }

  // ---- files -----------------------------------------------------------------

  /** Starts an upload attempt with its own R2 key. The declared length must match exactly. */
  async beginUpload(uploadHash: string, length: number): Promise<VaultResult<{ r2Key: string; size: number }>> {
    const now = Date.now();
    this.#reconcile(now);
    const file = this.#get<FileState>("file");
    if (!file || file.ready || !file.uploadHash || !same(file.uploadHash, uploadHash)) {
      return this.#finish(now, fail("not_found"));
    }
    if (length !== file.size) return this.#finish(now, fail("bad_request"));
    const tries = file.tries ?? 0;
    if (file.attempts.length >= MAX_UPLOAD_ATTEMPTS || tries >= MAX_UPLOAD_TRIES) return this.#finish(now, fail("conflict"));
    const r2Key = newR2Key();
    this.#put("file", { ...file, attempts: [...file.attempts, r2Key], tries: tries + 1 });
    return this.#finish(now, ok({ r2Key, size: file.size }));
  }

  /** Marks the first attempt to finish as the file; every other attempt is discarded. */
  async completeUpload(uploadHash: string, r2Key: string, storedSize: number): Promise<VaultResult<{ size: number }>> {
    const now = Date.now();
    this.#reconcile(now);
    const rec = this.#get<LiveRecord>("rec");
    const file = this.#get<FileState>("file");
    if (
      !rec ||
      !file ||
      file.ready ||
      !file.uploadHash ||
      !same(file.uploadHash, uploadHash) ||
      !file.attempts.includes(r2Key) ||
      storedSize !== file.size
    ) {
      return this.#finish(now, fail("not_found"));
    }
    this.#queueDelete(...file.attempts.filter((key) => key !== r2Key));
    this.#put("file", { ...file, ready: true, r2Key, attempts: [], uploadHash: null });
    if (rec.kind === "request" && rec.submission) {
      this.#put("rec", {
        ...rec,
        expiresAt: now + LIMITS.submissionRetentionMs,
        submission: { ...rec.submission, complete: true },
      } satisfies RequestRecord);
    }
    return this.#finish(now, ok({ size: file.size }));
  }

  /** Discards a failed or losing upload attempt. The live file is never touched. */
  async abortUpload(r2Key: string): Promise<void> {
    const now = Date.now();
    const file = this.#get<FileState>("file");
    if (file?.r2Key === r2Key) return;
    if (file) this.#put("file", { ...file, attempts: file.attempts.filter((key) => key !== r2Key) });
    this.#queueDelete(r2Key);
    await this.#schedule(now);
  }

  /** Authorizes one download attempt. A ticket allows a few retries until a download completes. */
  async redeemTicket(ticketHash: string): Promise<VaultResult<{ r2Key: string; size: number }>> {
    const now = Date.now();
    this.#reconcile(now);
    const file = this.#get<FileState>("file");
    const ticket = file?.ready ? liveTickets(file, now).find((t) => same(t.hash, ticketHash)) : undefined;
    if (!file?.r2Key || !ticket) return this.#finish(now, fail("not_found"));
    this.#put("file", { ...file, tickets: file.tickets.map((t) => (t === ticket ? { ...t, uses: t.uses + 1 } : t)) });
    return this.#finish(now, ok({ r2Key: file.r2Key, size: file.size }));
  }

  async ticketDone(ticketHash: string): Promise<void> {
    const now = Date.now();
    const file = this.#get<FileState>("file");
    if (file) {
      this.#put("file", {
        ...file,
        tickets: file.tickets.map((t) => (same(t.hash, ticketHash) ? { ...t, done: true } : t)),
      });
    }
    this.#reconcile(now);
    await this.#schedule(now);
  }

  /**
   * Whether a download already under way may go on: its file has not been revoked,
   * expired, locked or released since the ticket was redeemed.
   */
  async downloadAllowed(r2Key: string): Promise<boolean> {
    const now = Date.now();
    this.#reconcile(now);
    const file = this.#get<FileState>("file");
    await this.#schedule(now);
    return file?.ready === true && file.r2Key === r2Key;
  }
}
