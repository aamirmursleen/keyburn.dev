// The header's "Paste a secret, request or inbox link" box.
//
// It only ever navigates this tab to a whole link on this same origin whose path is /s, /m, /r
// or /i and that carries a #fragment (the key). The link is never sent anywhere: no request is
// made, nothing is stored, and the field is cleared before leaving the page.

const PATHS = new Set(["/s", "/m", "/r", "/i"]);

export type OpenableLink = { ok: true; href: string } | { ok: false; reason: "empty" | "invalid" | "elsewhere" };

export function openableLink(raw: string, origin: string): OpenableLink {
  const text = raw.trim();
  if (!text) return { ok: false, reason: "empty" };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { ok: false, reason: "invalid" };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false, reason: "invalid" };
  if (url.origin !== origin) return { ok: false, reason: "elsewhere" };
  if (url.username || url.password || url.search || !PATHS.has(url.pathname) || url.hash.length < 2) {
    return { ok: false, reason: "invalid" };
  }
  return { ok: true, href: url.href };
}

export function initOpenLink(): void {
  const form = document.getElementById("go-form");
  const input = document.getElementById("go-link");
  const error = document.getElementById("go-error");
  if (!(form instanceof HTMLFormElement) || !(input instanceof HTMLInputElement) || !error) return;

  const showError = (message: string | null): void => {
    error.textContent = message ?? "";
    error.hidden = message === null;
    if (message === null) input.removeAttribute("aria-invalid");
    else input.setAttribute("aria-invalid", "true");
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const link = openableLink(input.value, location.origin);
    if (link.ok) {
      input.value = "";
      showError(null);
      location.assign(link.href);
      return;
    }
    if (link.reason === "empty") {
      showError(null);
      input.focus();
      return;
    }
    showError(
      link.reason === "elsewhere"
        ? `Only links from ${location.host} open here.`
        : "That isn't a secret, receipt, request or inbox link. Paste the whole link, including everything after the #.",
    );
    input.focus();
  });
  input.addEventListener("input", () => showError(null));
  input.addEventListener("keydown", (event) => {
    if (event.key === "Escape") showError(null);
  });
  // Never leave a pasted link behind in a page restored from the back/forward cache.
  window.addEventListener("pagehide", () => {
    input.value = "";
  });
}
