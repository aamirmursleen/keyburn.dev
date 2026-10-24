import { b64urlEncode, utf8Encode } from "../shared/encoding";
import { HttpError } from "./http";

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEXTET = /^[0-9a-f]{1,4}$/;

/**
 * Stable per-client key for rate limits and quotas. IPv6 clients are grouped
 * by /64 because a single subscriber can usually rotate within it freely.
 */
export function clientKey(request: Request): string {
  const raw = request.headers.get("cf-connecting-ip")?.trim();
  if (!raw) return "unknown";
  if (!raw.includes(":")) return IPV4.test(raw) ? raw : "invalid";

  const address = (raw.split("%")[0] ?? "").toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
  if (mapped?.[1]) return mapped[1];

  const halves = address.split("::");
  if (halves.length > 2) return "invalid";
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 2 && fill === 0)) return "invalid";
  const groups = [...head, ...Array.from({ length: fill }, () => "0"), ...tail];
  if (groups.length !== 8 || !groups.every((group) => HEXTET.test(group))) return "invalid";
  return `${groups
    .slice(0, 4)
    .map((group) => parseInt(group, 16).toString(16))
    .join(":")}::/64`;
}

/**
 * The network an IPv6 client belongs to: its /48, the block one customer usually gets.
 * Rotating through many /64s still draws on this one shared budget. Null for IPv4.
 */
export function networkKey(request: Request): string | null {
  const client = clientKey(request);
  if (!client.endsWith("::/64")) return null;
  return `${client.slice(0, -"::/64".length).split(":").slice(0, 3).join(":")}::/48`;
}

let cached: { secret: string; key: Promise<CryptoKey> } | null = null;

/** HMAC of the client key, so raw IP addresses are never used as storage names. */
export async function hashClient(secret: string, key: string): Promise<string> {
  if (!secret) throw new HttpError(503, "unavailable");
  if (cached?.secret !== secret) {
    cached = {
      secret,
      key: crypto.subtle.importKey("raw", utf8Encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    };
  }
  const mac = await crypto.subtle.sign("HMAC", await cached.key, utf8Encode(key));
  return b64urlEncode(new Uint8Array(mac)).slice(0, 32);
}
