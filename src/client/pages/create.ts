import {
  aad,
  generatePassphrase,
  randomBytes,
  sealFile,
  sealPayload,
  secretAddress,
  secretKeys,
  tokenHash,
} from "../../shared/crypto";
import { b64urlEncode, type Bytes } from "../../shared/encoding";
import { LIMITS, type CreateSecretInput, type CreateSecretOutput, type KdfParams, type Sealed } from "../../shared/protocol";
import { post, uploadCiphertext } from "../api";
import {
  busy,
  byId,
  copyText,
  formatBytes,
  formatRemaining,
  h,
  only,
  safeFileName,
  showError,
  togglePassword,
} from "../dom";
import { filePicker, readFile } from "../file-picker";
import { links } from "../links";
import { errorMessage } from "../messages";
import { registerCreateTool } from "../webmcp";

interface ShareInput {
  text: string;
  file: File | null;
  passphrase: string | null;
  expiresIn: number;
  maxViews: number;
}

interface Shared {
  link: string;
  manage: string;
  expiresAt: number;
  maxViews: number;
  passphrase: string | null;
  file: { name: string; size: number } | null;
}

/** A created secret whose file upload failed and can be retried with the same token. */
interface PendingUpload {
  id: string;
  token: string;
  ciphertext: Bytes;
  shared: Shared;
}

type Progress = (label: string, fraction?: number) => void;
type Outcome = { ok: true; shared: Shared } | { ok: false; message: string; pending?: PendingUpload };

async function finishUpload(pending: PendingUpload, progress: Progress): Promise<Outcome> {
  const uploaded = await uploadCiphertext("secret", pending.id, pending.token, pending.ciphertext, (fraction) =>
    progress(`Uploading… ${Math.round(fraction * 100)}%`, fraction),
  );
  if (uploaded.ok) return { ok: true, shared: pending.shared };
  return { ok: false, message: `The upload failed. ${errorMessage(uploaded.error)}`, pending };
}

async function share(input: ShareInput, progress: Progress): Promise<Outcome> {
  const data = input.file ? await readFile(input.file) : null;
  const S = randomBytes(32);
  const { id, metaToken } = await secretAddress(S);
  const kdf: KdfParams | null = input.passphrase
    ? { alg: "PBKDF2-SHA256", iterations: LIMITS.pbkdf2MinIterations, salt: b64urlEncode(randomBytes(16)) }
    : null;
  if (kdf) progress("Strengthening passphrase…");
  const keys = await secretKeys(S, kdf && input.passphrase ? { passphrase: input.passphrase, kdf } : null);

  progress("Encrypting…");
  const fileMeta =
    input.file && data
      ? { name: safeFileName(input.file.name), type: input.file.type || "application/octet-stream", size: data.length }
      : null;
  let sealed: Sealed;
  try {
    sealed = await sealPayload(keys.textKey, aad.secretText(id), { v: 1, text: input.text, file: fileMeta });
  } catch (error) {
    if (error instanceof RangeError) {
      return { ok: false, message: "That text is too long (the limit is 64 KB). Attach it as a file instead." };
    }
    throw error;
  }
  const sealedFile = data ? await sealFile(keys.fileKey, aad.secretFile(id), data) : null;
  const manageToken = b64urlEncode(randomBytes(32));

  const body: CreateSecretInput = {
    id,
    metaHash: await tokenHash(metaToken),
    readHash: await tokenHash(keys.readToken),
    manageHash: await tokenHash(manageToken),
    iv: sealed.iv,
    ct: sealed.ct,
    expiresIn: input.expiresIn,
    maxViews: input.maxViews,
    kdf,
    file: sealedFile ? { size: sealedFile.ct.length, iv: sealedFile.iv } : null,
  };
  progress("Saving…");
  const created = await post<CreateSecretOutput>("secret/create", body);
  if (!created.ok) return { ok: false, message: errorMessage(created.error) };

  const shared: Shared = {
    link: links.secret(S),
    manage: links.manage(id, manageToken),
    expiresAt: created.data.expiresAt,
    maxViews: input.maxViews,
    passphrase: input.passphrase,
    file: fileMeta && { name: fileMeta.name, size: fileMeta.size },
  };
  if (sealedFile && created.data.uploadToken) {
    return finishUpload({ id, token: created.data.uploadToken, ciphertext: sealedFile.ct, shared }, progress);
  }
  return { ok: true, shared };
}

export function initCreate(): void {
  const compose = byId("compose");
  const created = byId("created");
  const form = byId<HTMLFormElement>("create-form");
  const secret = byId<HTMLTextAreaElement>("secret");
  const expires = byId<HTMLSelectElement>("expires");
  const views = byId<HTMLSelectElement>("views");
  const passphrase = byId<HTMLInputElement>("passphrase");
  const toggle = byId<HTMLButtonElement>("passphrase-toggle");
  const button = byId<HTMLButtonElement>("create-btn");
  const progressBar = byId<HTMLProgressElement>("create-progress");
  const error = byId("create-error");
  const secretLink = byId<HTMLInputElement>("secret-link");
  const manageLink = byId<HTMLInputElement>("manage-link");
  const passOut = byId<HTMLInputElement>("passphrase-out");
  let pending: PendingUpload | null = null;
  // Editing after a failed upload means the user wants to send something new, not retry.
  const discardPending = (): void => {
    if (!pending) return;
    pending = null;
    button.dataset.label = "Create secure link";
    if (!button.disabled) button.textContent = "Create secure link";
  };
  const files = filePicker("c", (message) => showError(error, message), discardPending);
  for (const field of [secret, passphrase, expires, views]) field.addEventListener("input", discardPending);

  toggle.addEventListener("click", () => togglePassword(passphrase, toggle));
  byId("passphrase-generate").addEventListener("click", () => {
    passphrase.value = generatePassphrase();
    if (passphrase.type === "password") togglePassword(passphrase, toggle);
  });
  for (const [buttonId, field] of [
    ["copy-secret-link", secretLink],
    ["copy-manage-link", manageLink],
    ["copy-passphrase", passOut],
  ] as const) {
    const copyButton = byId<HTMLButtonElement>(buttonId);
    copyButton.addEventListener("click", () => void copyText(field.value, copyButton, field));
  }
  byId("create-another").addEventListener("click", () => {
    secretLink.value = "";
    manageLink.value = "";
    passOut.value = "";
    only(compose, [compose, created]);
    secret.focus();
  });

  const progress: Progress = (label, fraction) => {
    button.textContent = label;
    if (fraction !== undefined) {
      progressBar.hidden = false;
      progressBar.value = fraction;
    }
  };

  function render(shared: Shared): void {
    secretLink.value = shared.link;
    manageLink.value = shared.manage;
    byId<HTMLAnchorElement>("open-manage").href = shared.manage;
    passOut.value = shared.passphrase ?? "";
    byId("created-passphrase").hidden = shared.passphrase === null;
    const chips = [
      `Expires in ${formatRemaining(shared.expiresAt)}`,
      shared.maxViews === 1 ? "Can be viewed once" : `Can be viewed ${shared.maxViews} times`,
    ];
    if (shared.passphrase) chips.push("Passphrase protected");
    if (shared.file) chips.push(`${shared.file.name} (${formatBytes(shared.file.size)})`);
    byId("created-summary").replaceChildren(...chips.map((text) => h("li", { text })));
    only(created, [compose, created]);
    window.scrollTo({ top: 0 });
    byId<HTMLButtonElement>("copy-secret-link").focus();
  }

  async function submit(): Promise<void> {
    showError(error, null);
    const text = secret.value;
    const file = files.get();
    const pass = passphrase.value;
    if (!pending && !text.trim() && !file) return showError(error, "Type a secret or attach a file.");
    if (!pending && pass && pass.length < 8) {
      return showError(error, "Use a passphrase of at least 8 characters, or leave it empty.");
    }

    busy(button, "Encrypting…");
    try {
      const outcome = pending
        ? await finishUpload(pending, progress)
        : await share({ text, file, passphrase: pass || null, expiresIn: Number(expires.value), maxViews: Number(views.value) }, progress);
      if (!outcome.ok) {
        pending = outcome.pending ?? null;
        if (pending) button.dataset.label = "Retry upload";
        return showError(error, outcome.message);
      }
      pending = null;
      button.dataset.label = "Create secure link";
      secret.value = "";
      passphrase.value = "";
      files.reset();
      render(outcome.shared);
    } catch {
      showError(error, "Something went wrong while encrypting. Please try again.");
    } finally {
      busy(button, null);
      progressBar.hidden = true;
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void submit();
  });

  // An AI agent in this tab can create a text secret too; the result is shown like any other.
  registerCreateTool(async (input) => {
    try {
      const outcome = await share(
        {
          text: input.text,
          file: null,
          passphrase: input.passphrase ? generatePassphrase() : null,
          expiresIn: input.expiresIn,
          maxViews: input.maxViews,
        },
        () => undefined,
      );
      if (!outcome.ok) return { ok: false, message: outcome.message };
      render(outcome.shared);
      const { link, manage, expiresAt, passphrase: generated } = outcome.shared;
      return { ok: true, link, receipt: manage, expiresAt, passphrase: generated };
    } catch {
      return { ok: false, message: "Something went wrong while encrypting." };
    }
  });
}
