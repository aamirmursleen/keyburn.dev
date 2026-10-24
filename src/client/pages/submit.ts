import { aad, openPayload, requestAddress, sealFile, sealPayload, senderKeys } from "../../shared/crypto";
import { b64urlEncode, type Bytes } from "../../shared/encoding";
import { lookupWithLegacyId } from "../../shared/legacy";
import type { GoneReason, RequestInfoOutput, Sealed, SubmitRequestOutput } from "../../shared/protocol";
import { post, uploadCiphertext } from "../api";
import { busy, byId, only, safeFileName, showError } from "../dom";
import { filePicker, readFile } from "../file-picker";
import { forgetFragment, splitKeys, takeFragment } from "../links";
import { errorMessage } from "../messages";

type ClosedReason = GoneReason | "submitted" | "not_found" | "incomplete";

const CLOSED: Record<ClosedReason, { title: string; body: string }> = {
  submitted: {
    title: "This request was already answered",
    body: "A response has already been sent through this link. If you need to send something else, ask for a new link.",
  },
  opened: {
    title: "This request was already answered",
    body: "A response has already been sent and received. If you need to send something else, ask for a new link.",
  },
  expired: { title: "This request link has expired", body: "Ask the person who sent it for a new link." },
  revoked: { title: "This request was cancelled", body: "The person who sent it cancelled the request." },
  viewed: { title: "This request was already answered", body: "Ask the person who sent it for a new link." },
  locked: { title: "This request is closed", body: "Ask the person who sent it for a new link." },
  abandoned: { title: "This request is closed", body: "Ask the person who sent it for a new link." },
  not_found: { title: "This request link isn't valid", body: "It may have expired, or part of the link may be missing." },
  incomplete: {
    title: "This link is incomplete",
    body: "Part of the link is missing. Make sure you copied the whole link, including everything after the # sign.",
  },
};

export function initSubmit(): void {
  const views = ["r-loading", "r-compose", "r-sent", "r-closed", "r-fail"].map((id) => byId(id));
  const [loading, compose, sent, closed, fail] = views as [HTMLElement, HTMLElement, HTMLElement, HTMLElement, HTMLElement];

  const showClosed = (reason: ClosedReason): void => {
    byId("r-closed-title").textContent = CLOSED[reason].title;
    byId("r-closed-body").textContent = CLOSED[reason].body;
    only(closed, views);
  };

  const parts = splitKeys(takeFragment("r"), [32, 65]);
  const [Q, pub] = parts ?? [];
  if (!Q || !pub || pub[0] !== 4) return showClosed("incomplete");
  run(Q, pub);

  function run(Q: Bytes, pub: Bytes): void {
    const form = byId<HTMLFormElement>("r-form");
    const secret = byId<HTMLTextAreaElement>("r-secret");
    const button = byId<HTMLButtonElement>("r-btn");
    const progressBar = byId<HTMLProgressElement>("r-progress");
    const error = byId("r-error");
    let address: Awaited<ReturnType<typeof requestAddress>> | null = null;
    let pendingUpload: { token: string; ciphertext: Bytes } | null = null;
    const discardPending = (): void => {
      if (!pendingUpload) return;
      pendingUpload = null;
      button.dataset.label = "Encrypt and send";
      if (!button.disabled) button.textContent = "Encrypt and send";
    };
    const files = filePicker("r", (message) => showError(error, message), discardPending);
    secret.addEventListener("input", discardPending);

    async function load(): Promise<void> {
      only(loading, views);
      address ??= await requestAddress(Q);
      const { submitToken } = address;
      const { id, res } = await lookupWithLegacyId(address, (id) => post<RequestInfoOutput>("request/info", { id, submitToken }));
      if (res.ok) address = { ...address, id, legacyId: id };
      if (!res.ok) {
        if (res.error === "not_found") return showClosed("not_found");
        byId("r-fail-body").textContent = errorMessage(res.error);
        return only(fail, views);
      }
      if (res.data.state === "closed") return showClosed(res.data.reason);
      if (res.data.note) {
        try {
          const note = await openPayload(address.noteKey, aad.requestNote(address.id), res.data.note);
          byId("r-note").textContent = note.text;
          byId("r-note-box").hidden = note.text.length === 0;
        } catch {
          byId("r-note-box").hidden = true;
        }
      }
      only(compose, views);
    }

    async function upload(id: string, pending: { token: string; ciphertext: Bytes }): Promise<boolean> {
      const result = await uploadCiphertext("request", id, pending.token, pending.ciphertext, (fraction) => {
        button.textContent = `Uploading… ${Math.round(fraction * 100)}%`;
        progressBar.hidden = false;
        progressBar.value = fraction;
      });
      if (result.ok) return true;
      pendingUpload = pending;
      button.dataset.label = "Retry upload";
      showError(error, `The upload failed. ${errorMessage(result.error)}`);
      return false;
    }

    async function send(): Promise<void> {
      if (!address) return;
      showError(error, null);
      if (pendingUpload) {
        busy(button, "Uploading…");
        try {
          if (await upload(address.id, pendingUpload)) finish();
        } finally {
          busy(button, null);
          progressBar.hidden = true;
        }
        return;
      }

      const text = secret.value;
      const file = files.get();
      if (!text.trim() && !file) return showError(error, "Type a secret or attach a file.");
      busy(button, "Encrypting…");
      try {
        const keys = await senderKeys(pub, Q, address.id);
        const data = file ? await readFile(file) : null;
        const fileMeta =
          file && data ? { name: safeFileName(file.name), type: file.type || "application/octet-stream", size: data.length } : null;
        let sealed: Sealed;
        try {
          sealed = await sealPayload(keys.textKey, aad.requestText(address.id), { v: 1, text, file: fileMeta });
        } catch (error_) {
          if (error_ instanceof RangeError) return showError(error, "That text is too long (the limit is 64 KB). Attach it as a file instead.");
          throw error_;
        }
        const sealedFile = data ? await sealFile(keys.fileKey, aad.requestFile(address.id), data) : null;
        const res = await post<SubmitRequestOutput>("request/submit", {
          id: address.id,
          submitToken: address.submitToken,
          ephPub: b64urlEncode(keys.ephPub),
          iv: sealed.iv,
          ct: sealed.ct,
          file: sealedFile ? { size: sealedFile.ct.length, iv: sealedFile.iv } : null,
        });
        if (!res.ok) {
          if (res.error === "conflict") return showClosed("submitted");
          if (res.error === "not_found") return showClosed("not_found");
          return showError(error, errorMessage(res.error));
        }
        if (sealedFile && res.data.uploadToken) {
          const uploaded = await upload(address.id, { token: res.data.uploadToken, ciphertext: sealedFile.ct });
          if (!uploaded) return;
        }
        finish();
      } catch {
        showError(error, "Something went wrong while encrypting. Please try again.");
      } finally {
        busy(button, null);
        progressBar.hidden = true;
      }
    }

    function finish(): void {
      pendingUpload = null;
      secret.value = "";
      files.reset();
      forgetFragment("r");
      only(sent, views);
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void send();
    });
    byId("r-retry").addEventListener("click", () => void load());
    void load().catch(() => {
      byId("r-fail-body").textContent = errorMessage("network");
      only(fail, views);
    });
  }
}
