import { aad, inboxToken, newRequester, requestAddress, sealPayload, tokenHash } from "../../shared/crypto";
import { b64urlEncode } from "../../shared/encoding";
import { LIMITS, type CreateRequestInput, type CreateRequestOutput } from "../../shared/protocol";
import { post } from "../api";
import { busy, byId, copyText, only, showError } from "../dom";
import { links } from "../links";
import { errorMessage } from "../messages";

export function initRequest(): void {
  const compose = byId("q-compose");
  const created = byId("q-created");
  const form = byId<HTMLFormElement>("q-form");
  const note = byId<HTMLTextAreaElement>("q-note");
  const expires = byId<HTMLSelectElement>("q-expires");
  const button = byId<HTMLButtonElement>("q-btn");
  const error = byId("q-error");
  const clientLink = byId<HTMLInputElement>("q-client-link");
  const inboxLink = byId<HTMLInputElement>("q-inbox-link");

  for (const [buttonId, field] of [
    ["q-copy-client", clientLink],
    ["q-copy-inbox", inboxLink],
  ] as const) {
    const copyButton = byId<HTMLButtonElement>(buttonId);
    copyButton.addEventListener("click", () => void copyText(field.value, copyButton, field));
  }
  byId("q-another").addEventListener("click", () => {
    clientLink.value = "";
    inboxLink.value = "";
    only(compose, [compose, created]);
    note.focus();
  });

  async function create(): Promise<void> {
    showError(error, null);
    const text = note.value.trim();
    if (text.length > LIMITS.noteMaxChars) return showError(error, "Keep the note under 1,000 characters.");

    busy(button, "Creating…");
    try {
      const requester = await newRequester();
      const address = await requestAddress(requester.Q);
      const inbox = await inboxToken(requester.Q, requester.d);
      const sealedNote = text
        ? await sealPayload(address.noteKey, aad.requestNote(address.id), { v: 1, text, file: null })
        : null;
      const body: CreateRequestInput = {
        id: address.id,
        submitHash: await tokenHash(address.submitToken),
        inboxHash: await tokenHash(inbox),
        pub: b64urlEncode(requester.pub),
        note: sealedNote,
        expiresIn: Number(expires.value),
      };
      const res = await post<CreateRequestOutput>("request/create", body);
      if (!res.ok) return showError(error, errorMessage(res.error));

      clientLink.value = links.request(requester.Q, requester.pub);
      inboxLink.value = links.inbox(requester.Q, requester.d);
      byId<HTMLAnchorElement>("q-open-inbox").href = inboxLink.value;
      note.value = "";
      only(created, [compose, created]);
      window.scrollTo({ top: 0 });
      byId<HTMLButtonElement>("q-copy-client").focus();
    } catch {
      showError(error, "Something went wrong. Please try again.");
    } finally {
      busy(button, null);
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void create();
  });
}
