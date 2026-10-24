import { LIMITS } from "./protocol";

/**
 * Makes a sender-chosen file name safe to save and to display: strips path
 * separators, control characters, zero-width characters and Unicode direction
 * marks and overrides used to disguise extensions (e.g. "invoice\u202efdp.exe").
 */
export function safeFileName(name: string): string {
  const cleaned = name
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]+/g, "_")
    .replace(/^[.\s]+/, "")
    .trim()
    .slice(0, LIMITS.fileNameMaxChars);
  return cleaned || "download";
}
