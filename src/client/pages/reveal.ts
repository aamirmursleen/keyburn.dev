import { aad, assertKdf, openPayload, secretAddress, secretKeys } from "../../shared/crypto";
import type { Bytes } from "../../shared/encoding";
import { lookupWithLegacyId } from "../../shared/legacy";
import type { GoneReason, OpenSecretOutput, SecretMetaOutput } from "../../shared/protocol";
import { post } from "../api";
import { showContent } from "../content";
import { busy, byId, formatBytes, formatRemaining, h, only, plural, showError } from "../dom";
import { splitKeys, takeFragment } from "../links";
import { errorMessage, goneMessage } from "../messages";

type ActiveMeta = Extract<SecretMetaOutput, { state: "active" }>;

export function initReveal(): void {
  const views = ["v-loading", "v-ready", "v-revealed", "v-gone", "v-fail"].map((id) => byId(id));
  const [loading, ready, revealed, gone, fail] = views as [HTMLElement, HTMLElement, HTMLElement, HTMLElement, HTMLElement];

  const showGone = (reason: GoneReason | "not_found" | "incomplete", at?: number): void => {
    const message = goneMessage(reason, at);
    byId("v-gone-title").textContent = message.title;
    byId("v-gone-body").textContent = message.body;
    only(gone, views);
  };
  const showFail = (message: string): void => {
    byId("v-fail-body").textContent = message;
    only(fail, views);
  };

  // The key is wiped from the address bar right away and never persisted.
  const S = splitKeys(takeFragment(), [32])?.[0];
  if (!S) return showGone("incomplete");
  run(S);

  function run(S: Bytes): void {
    const form = byId<HTMLFormElement>("v-form");
    const passField = byId("v-passphrase-field");
    const passInput = byId<HTMLInputElement>("v-passphrase");
    const button = byId<HTMLButtonElement>("v-reveal");
    const error = byId("v-error");
    let address: Awaited<ReturnType<typeof secretAddress>> | null = null;
    let meta: ActiveMeta | null = null;

    async function load(): Promise<void> {
      only(loading, views);
      address ??= await secretAddress(S);
      const { metaToken } = address;
      const { id, res } = await lookupWithLegacyId(address, (id) => post<SecretMetaOutput>("secret/meta", { id, metaToken }));
      if (res.ok) address = { ...address, id, legacyId: id };
      if (!res.ok) return res.error === "not_found" ? showGone("not_found") : showFail(errorMessage(res.error));
      if (res.data.state === "gone") return showGone(res.data.reason, res.data.at);
      meta = res.data;
      renderReady(meta);
    }

    function renderReady(m: ActiveMeta): void {
      const facts = [
        m.viewsLeft === 1 ? "Can be viewed once" : `Can be viewed ${m.viewsLeft} more times`,
        `Expires in ${formatRemaining(m.expiresAt)}`,
      ];
      if (m.kdf) facts.push("Passphrase protected");
      if (m.file) facts.push(`Includes a file (${formatBytes(m.file.size)})`);
      byId("v-facts").replaceChildren(...facts.map((text) => h("li", { text })));
      passField.hidden = !m.kdf;
      byId("v-warning").textContent =
        m.viewsLeft === 1
          ? "As soon as you reveal it, it's permanently deleted from our servers, so have somewhere safe ready to save it."
          : `Each reveal uses up one of the ${m.viewsLeft} remaining views.`;
      only(ready, views);
      if (m.kdf) passInput.focus();
    }

    async function reveal(): Promise<void> {
      if (!meta || !address) return;
      showError(error, null);
      const passphrase = passInput.value;
      if (meta.kdf && !passphrase) return showError(error, "Enter the passphrase the sender gave you.");

      busy(button, meta.kdf ? "Unlocking…" : "Decrypting…");
      try {
        // Refuse weakened parameters even if a compromised server sent them.
        if (meta.kdf) assertKdf(meta.kdf);
        const keys = await secretKeys(S, meta.kdf ? { passphrase, kdf: meta.kdf } : null);
        const res = await post<OpenSecretOutput>("secret/open", {
          id: address.id,
          metaToken: address.metaToken,
          readToken: keys.readToken,
        });
        if (!res.ok) {
          if (res.error === "wrong_passphrase") {
            const left = res.attemptsLeft ?? 0;
            if (left <= 0) return showGone("locked");
            meta = { ...meta, attemptsLeft: left };
            passInput.select();
            return showError(error, `Wrong passphrase. ${plural(left, "attempt")} left before the secret is destroyed.`);
          }
          if (res.error === "not_found") return await load();
          return showError(error, errorMessage(res.error));
        }

        const payload = await openPayload(keys.textKey, aad.secretText(address.id), res.data);
        passInput.value = "";
        const file = res.data.file;
        showContent(
          "v",
          payload,
          file ? { kind: "secret", id: address.id, ticket: file, key: keys.fileKey, aad: aad.secretFile(address.id) } : null,
        );
        byId("v-after").textContent =
          res.data.viewsLeft > 0
            ? `It can be viewed ${plural(res.data.viewsLeft, "more time")} before it's deleted.`
            : file
              ? "This secret has been deleted from our servers. Download the file now: the download works for 15 minutes."
              : "This secret has been permanently deleted from our servers. Save it somewhere safe before you leave this page.";
        only(revealed, views);
      } catch {
        showFail("This secret couldn't be decrypted. The link may be damaged or altered.");
      } finally {
        busy(button, null);
      }
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void reveal();
    });
    byId("v-retry").addEventListener("click", () => void load().catch(() => showFail(errorMessage("network"))));
    void load().catch(() => showFail(errorMessage("network")));
  }
}
