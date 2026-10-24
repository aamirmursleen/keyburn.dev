// Minimal DOM helpers. Text is only ever set via textContent and elements via
// createElement, never HTML strings, so the page runs under Trusted Types 'none'.

import { safeFileName } from "../shared/names";

export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing element #${id}`);
  return node as T;
}

/** Shows `view` and hides every other element in `views`. */
export function only(view: HTMLElement, views: readonly HTMLElement[]): void {
  for (const candidate of views) candidate.hidden = candidate !== view;
}

type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; text?: string; attrs?: Record<string, string> } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.class) node.className = props.class;
  if (props.text !== undefined) node.textContent = props.text;
  for (const [name, value] of Object.entries(props.attrs ?? {})) node.setAttribute(name, value);
  for (const child of children) if (child) node.append(child);
  return node;
}

/** Disables a button while work is in progress and restores its label afterwards. */
export function busy(button: HTMLButtonElement, label: string | null): void {
  if (label === null) {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    if (button.dataset.label !== undefined) button.textContent = button.dataset.label;
    return;
  }
  if (button.dataset.label === undefined) button.dataset.label = button.textContent ?? "";
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.textContent = label;
}

export function showError(target: HTMLElement, message: string | null): void {
  target.textContent = message ?? "";
  target.hidden = message === null;
}

export async function copyText(text: string, button: HTMLButtonElement, field?: HTMLInputElement): Promise<void> {
  const original = button.dataset.copyLabel ?? button.textContent ?? "Copy";
  button.dataset.copyLabel = original;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied ✓";
  } catch {
    // Clipboard blocked: select the text so the user can copy it manually.
    field?.select();
    button.textContent = "Press Ctrl/⌘+C";
  }
  setTimeout(() => {
    button.textContent = original;
  }, 1800);
}

export function togglePassword(input: HTMLInputElement, button: HTMLButtonElement): void {
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  button.textContent = reveal ? "Hide" : "Show";
  button.setAttribute("aria-pressed", String(reveal));
}

export function confirmDialog(options: { title: string; body: string; confirm: string }): Promise<boolean> {
  return new Promise((resolve) => {
    const cancel = h("button", { class: "btn", text: "Cancel", attrs: { type: "button" } });
    const accept = h("button", { class: "btn danger", text: options.confirm, attrs: { type: "button" } });
    const title = h("h2", { text: options.title, attrs: { id: "dialog-title" } });
    const dialog = h(
      "dialog",
      { class: "dialog", attrs: { "aria-labelledby": "dialog-title" } },
      title,
      h("p", { class: "muted", text: options.body }),
      h("div", { class: "dialog-actions" }, cancel, accept),
    );
    const finish = (result: boolean): void => {
      dialog.close();
      dialog.remove();
      resolve(result);
    };
    cancel.addEventListener("click", () => finish(false));
    accept.addEventListener("click", () => finish(true));
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      finish(false);
    });
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function formatWhen(timestamp: number): string {
  return dateTime.format(timestamp);
}

export function formatRemaining(until: number): string {
  const minutes = Math.max(0, Math.round((until - Date.now()) / 60_000));
  if (minutes < 1) return "less than a minute";
  if (minutes < 90) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hours`;
  return `${Math.round(hours / 24)} days`;
}

export function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

export function countryLabel(code: string | null): string {
  if (!code) return "an unknown location";
  if (code === "T1") return "the Tor network";
  try {
    return new Intl.DisplayNames(undefined, { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

export { safeFileName } from "../shared/names";

export function saveBytes(bytes: Uint8Array<ArrayBuffer>, fileName: string): void {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const link = h("a", { attrs: { href: url, download: safeFileName(fileName) } });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
