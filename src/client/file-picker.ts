import { LIMITS } from "../shared/protocol";
import { byId, formatBytes } from "./dom";

export interface FilePicker {
  get(): File | null;
  reset(): void;
}

/** Wires up the "<prefix>-dropzone / -file / -file-chip" markup used on the compose pages. */
export function filePicker(
  prefix: string,
  onError: (message: string | null) => void,
  onChange: () => void = () => {},
): FilePicker {
  const zone = byId(`${prefix}-dropzone`);
  const input = byId<HTMLInputElement>(`${prefix}-file`);
  const chip = byId(`${prefix}-file-chip`);
  const name = byId(`${prefix}-file-name`);
  const size = byId(`${prefix}-file-size`);
  const remove = byId<HTMLButtonElement>(`${prefix}-file-remove`);
  let current: File | null = null;

  const choose = (file: File | null): void => {
    let accepted = file;
    if (file && file.size > LIMITS.fileMaxBytes) {
      onError(`That file is ${formatBytes(file.size)}. The limit is 25 MB.`);
      accepted = null;
    } else if (file && file.size === 0) {
      onError("That file is empty.");
      accepted = null;
    } else {
      onError(null);
    }
    current = accepted;
    input.value = "";
    name.textContent = accepted?.name ?? "";
    size.textContent = accepted ? formatBytes(accepted.size) : "";
    chip.hidden = accepted === null;
    zone.hidden = accepted !== null;
    onChange();
  };

  input.addEventListener("change", () => choose(input.files?.[0] ?? null));
  remove.addEventListener("click", () => choose(null));
  for (const type of ["dragenter", "dragover"] as const) {
    zone.addEventListener(type, (event) => {
      event.preventDefault();
      zone.classList.add("dragging");
    });
  }
  zone.addEventListener("dragleave", () => zone.classList.remove("dragging"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("dragging");
    const file = event.dataTransfer?.files[0];
    if (file) choose(file);
  });
  // A file dropped anywhere else must not navigate away and lose the form.
  window.addEventListener("dragover", (event) => event.preventDefault());
  window.addEventListener("drop", (event) => event.preventDefault());

  return { get: () => current, reset: () => choose(null) };
}

export async function readFile(file: File): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await file.arrayBuffer());
}
