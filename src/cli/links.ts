import { b64urlDecode, b64urlEncode, isB64url, type Bytes } from "../shared/encoding";
import { CliError } from "./errors";

/** The only servers the tool talks to. */
export const DEFAULT_ORIGINS: readonly string[] = ["https://secret.nafran.com", "https://secrets.nafran.com"];

/**
 * Trusted origins. Configuration may add one loopback origin for local testing; a link can
 * never add an origin, and no other server can be configured.
 */
export function trustedOrigins(extra?: string | null): readonly string[] {
  if (!extra) return DEFAULT_ORIGINS;
  let url: URL | null = null;
  try {
    url = new URL(extra);
  } catch {
    url = null;
  }
  const loopback = url && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    !url ||
    !loopback ||
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new CliError("untrusted_origin", "OSSS_ORIGIN may only name a loopback test server, e.g. http://localhost:8787.");
  }
  return [...DEFAULT_ORIGINS, url.origin];
}

export interface SecretLink {
  origin: string;
  S: Bytes;
}

export interface ReceiptLink {
  origin: string;
  id: string;
  manageToken: string;
}

/** Trims punctuation that commonly surrounds a pasted link (none of it can occur in a key). */
export function trimLink(text: string): string {
  return text.replace(/^[<("'[{]+/, "").replace(/[>)"'\]}.,;:!?]+$/, "");
}

function locate(input: string, origins: readonly string[], path: string): { origin: string; fragment: string } {
  const text = trimLink(input.trim());
  let url: URL;
  try {
    if (text.length > 512) throw new Error("too long");
    url = new URL(text);
  } catch {
    throw new CliError("bad_link", "That isn't a complete link. Copy the whole link, including everything after #.");
  }
  if (!origins.includes(url.origin) || url.username || url.password) {
    throw new CliError("untrusted_origin", "Only links from secret.nafran.com or secrets.nafran.com are accepted.");
  }
  if (url.pathname !== path || url.search) {
    throw new CliError("bad_link", "That isn't the right kind of link for this command.");
  }
  return { origin: url.origin, fragment: url.hash.slice(1) };
}

export function parseSecretLink(input: string, origins: readonly string[]): SecretLink {
  const { origin, fragment } = locate(input, origins, "/s");
  if (!isB64url(fragment, 32)) throw new CliError("bad_link", "This link is incomplete or damaged.");
  return { origin, S: b64urlDecode(fragment) };
}

export function parseReceiptLink(input: string, origins: readonly string[]): ReceiptLink {
  const { origin, fragment } = locate(input, origins, "/m");
  const [id, manageToken, ...rest] = fragment.split(".");
  if (rest.length > 0 || !id || !manageToken || !isB64url(id, 16) || !isB64url(manageToken, 32)) {
    throw new CliError("bad_link", "This receipt link is incomplete or damaged.");
  }
  return { origin, id, manageToken };
}

export const links = {
  secret: (origin: string, S: Bytes): string => `${origin}/s#${b64urlEncode(S)}`,
  receipt: (origin: string, id: string, manageToken: string): string => `${origin}/m#${id}.${manageToken}`,
};
