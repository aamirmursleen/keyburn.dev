import { b64urlDecode, b64urlEncode, isB64url, type Bytes } from "../shared/encoding";

const STORAGE_PREFIX = "osss:";

/**
 * Reads key material from the URL fragment and immediately removes it from
 * the address bar (protects against shoulder-surfing, screen sharing and
 * copying the URL bar). With `persistAs`, the fragment is kept in this tab's
 * sessionStorage so a reload still works.
 */
export function takeFragment(persistAs?: string): string | null {
  const raw = location.hash.length > 1 ? location.hash.slice(1) : null;
  if (raw) history.replaceState(null, "", location.pathname);
  if (!persistAs) return raw;
  try {
    if (raw) sessionStorage.setItem(STORAGE_PREFIX + persistAs, raw);
    // Only a reload or back/forward visit restores the key. A fresh navigation, such as
    // another page sending this tab to /i, gets nothing.
    return raw ?? (revisited() ? sessionStorage.getItem(STORAGE_PREFIX + persistAs) : null);
  } catch {
    return raw;
  }
}

function revisited(): boolean {
  const [entry] = performance.getEntriesByType("navigation") as PerformanceNavigationTiming[];
  return entry?.type === "reload" || entry?.type === "back_forward";
}

export function forgetFragment(persistAs: string): void {
  try {
    sessionStorage.removeItem(STORAGE_PREFIX + persistAs);
  } catch {
    // Storage unavailable (private mode); nothing was persisted.
  }
}

/** Splits "a.b.c" into exact-size byte arrays, or null if anything is malformed. */
export function splitKeys(fragment: string | null, sizes: readonly number[]): Bytes[] | null {
  if (!fragment) return null;
  const parts = fragment.split(".");
  if (parts.length !== sizes.length) return null;
  const out: Bytes[] = [];
  for (const [index, part] of parts.entries()) {
    const size = sizes[index];
    if (size === undefined || !isB64url(part, size)) return null;
    out.push(b64urlDecode(part));
  }
  return out;
}

export const links = {
  secret: (S: Bytes): string => `${location.origin}/s#${b64urlEncode(S)}`,
  manage: (id: string, token: string): string => `${location.origin}/m#${id}.${token}`,
  request: (Q: Bytes, pub: Bytes): string => `${location.origin}/r#${b64urlEncode(Q)}.${b64urlEncode(pub)}`,
  inbox: (Q: Bytes, d: Bytes): string => `${location.origin}/i#${b64urlEncode(Q)}.${b64urlEncode(d)}`,
};
