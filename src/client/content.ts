import { openFile } from "../shared/crypto";
import type { FileTicket, Payload } from "../shared/protocol";
import { downloadCiphertext } from "./api";
import { busy, byId, copyText, formatBytes, safeFileName, saveBytes, showError } from "./dom";
import { errorMessage } from "./messages";

export interface EncryptedFile {
  kind: "secret" | "request";
  id: string;
  ticket: FileTicket;
  key: CryptoKey;
  aad: string;
}

/** Renders decrypted content into the "<prefix>-text… / <prefix>-file…" markup. */
export function showContent(prefix: string, payload: Payload, file: EncryptedFile | null): void {
  const textBlock = byId(`${prefix}-text-block`);
  const text = byId(`${prefix}-text`);
  const copy = byId<HTMLButtonElement>(`${prefix}-copy`);
  const toggle = byId<HTMLButtonElement>(`${prefix}-toggle`);

  text.textContent = payload.text;
  textBlock.hidden = payload.text.length === 0;
  copy.addEventListener("click", () => void copyText(payload.text, copy));
  toggle.addEventListener("click", () => {
    const concealed = text.classList.toggle("concealed");
    toggle.textContent = concealed ? "Show" : "Hide";
    toggle.setAttribute("aria-pressed", String(concealed));
  });

  const fileBox = byId(`${prefix}-file`);
  fileBox.hidden = !(file && payload.file);
  if (file && payload.file) wireDownload(prefix, file, payload.file);

  // Wipe plaintext from the DOM when the page is left (also keeps it out of the back/forward cache).
  window.addEventListener("pagehide", () => {
    text.textContent = "";
  });
}

function wireDownload(prefix: string, file: EncryptedFile, meta: NonNullable<Payload["file"]>): void {
  byId(`${prefix}-file-name`).textContent = safeFileName(meta.name);
  byId(`${prefix}-file-size`).textContent = formatBytes(meta.size);
  const button = byId<HTMLButtonElement>(`${prefix}-download`);
  const progress = byId<HTMLProgressElement>(`${prefix}-progress`);
  const error = byId(`${prefix}-download-error`);
  let done = false;

  button.addEventListener("click", async () => {
    if (done) return;
    busy(button, "Downloading…");
    showError(error, null);
    progress.value = 0;
    progress.hidden = false;
    try {
      const result = await downloadCiphertext(file.kind, file.id, file.ticket.ticket, file.ticket.size, (fraction) => {
        progress.value = fraction;
      });
      if (!result.ok) {
        showError(
          error,
          result.error === "not_found"
            ? "This download is no longer available. Files can be downloaded for 15 minutes after opening."
            : errorMessage(result.error),
        );
        return;
      }
      const plain = await openFile(file.key, file.aad, file.ticket.iv, result.data, meta.size);
      saveBytes(plain, meta.name);
      done = true;
      button.dataset.label = "Downloaded ✓";
    } catch {
      showError(error, "The file couldn't be decrypted. It may have been damaged or altered.");
    } finally {
      busy(button, null);
      button.disabled = done;
      progress.hidden = true;
    }
  });
}
