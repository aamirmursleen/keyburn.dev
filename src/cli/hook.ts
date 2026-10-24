// A Claude Code UserPromptSubmit hook that keeps secret links out of the conversation: when a
// prompt contains one, the link is opened on this computer, the prompt is blocked (so it never
// reaches the model), and the user gets the same message back with a handle in place of the link.

import { CliError } from "./errors";
import { trimLink } from "./links";
import type { OpenSummary } from "./mcp";

/** Pages whose links carry a key or token after "#". */
const CAPABILITY_PATHS = new Set(["/s", "/m", "/r", "/i"]);
/** Anything shaped like host/x#fragment, with or without a scheme. */
const LINK_LIKE = /(?:https?:\/\/)?[a-z0-9.-]+(?::\d{1,5})?\/[smri]#[^\s"'<>()[\]{}`\\]+/gi;

export interface HookPlan {
  /** Whether the prompt contained capability links and must not reach the model. */
  block: boolean;
  /** Shown to the user only (Claude Code doesn't add it to the model's context). */
  reason: string;
  /** The prompt with every link replaced, ready to send again. */
  rewritten: string;
}

/** The link as written in the prompt and as a full URL, if it points at a trusted origin. */
function capability(raw: string, origins: readonly string[]): { text: string; url: URL } | null {
  const text = trimLink(raw);
  let url: URL;
  try {
    url = new URL(/^https?:\/\//i.test(text) ? text : `https://${text}`);
  } catch {
    return null;
  }
  return origins.includes(url.origin) && CAPABILITY_PATHS.has(url.pathname) && url.hash.length > 1 ? { text, url } : null;
}

function describe(summary: OpenSummary): string {
  const what = summary.contains === "environment variables" ? `variables: ${summary.variables.join(", ")}` : "OSSS_SECRET";
  return `${summary.handle} (osss handle; ${what}${summary.hasFile ? ", file: OSSS_SECRET_FILE" : ""})`;
}

/**
 * Finds capability links for the trusted origins, opens each secret once (in parallel, however
 * many times and in whatever spelling it appears), and plans the block. Every link found blocks
 * the prompt, whatever the outcome of opening it, because a link that couldn't be opened may
 * still work for someone else.
 */
export async function planHook(prompt: string, origins: readonly string[], open: (link: string) => Promise<OpenSummary>): Promise<HookPlan> {
  // One entry per capability: both hosts serve the same secrets, so the key alone identifies one.
  const capabilities = new Map<string, { url: URL; spellings: Set<string> }>();
  for (const match of prompt.match(LINK_LIKE) ?? []) {
    const link = capability(match, origins);
    if (!link) continue;
    const identity = `${link.url.pathname}${link.url.hash}`;
    const entry = capabilities.get(identity) ?? { url: link.url, spellings: new Set<string>() };
    entry.spellings.add(link.text);
    capabilities.set(identity, entry);
  }
  if (capabilities.size === 0) return { block: false, reason: "", rewritten: prompt };

  const outcomes = await Promise.all(
    [...capabilities.values()].map(async ({ url }): Promise<{ replacement: string; note: string }> => {
      if (url.pathname !== "/s") {
        return {
          replacement: "[private link removed]",
          note: "A receipt, request or inbox link was removed: those only work in a browser. Open it there instead of sharing it with Claude.",
        };
      }
      try {
        const summary = await open(url.href);
        return {
          replacement: describe(summary),
          note: `Opened a secret on this computer as ${summary.handle}${summary.viewsLeft === 0 ? "; it is now deleted from the server" : ""}.`,
        };
      } catch (error) {
        return {
          replacement: "[secret link removed]",
          note:
            error instanceof CliError && error.code === "passphrase_required"
              ? "A secret needs a passphrase: run `node ~/.osss/osss.mjs open` in another terminal, then give Claude the handle it prints."
              : `A secret link couldn't be opened: ${error instanceof CliError ? error.message : "unexpected error."}`,
        };
      }
    }),
  );

  // Replace longer spellings first, so one spelling inside another can't leave a fragment behind.
  const replacements: [string, string][] = [];
  [...capabilities.values()].forEach(({ spellings }, i) => {
    for (const spelling of spellings) replacements.push([spelling, (outcomes[i] as { replacement: string }).replacement]);
  });
  replacements.sort((a, b) => b[0].length - a[0].length);
  let rewritten = prompt;
  for (const [spelling, replacement] of replacements) rewritten = rewritten.split(spelling).join(replacement);

  const count = capabilities.size;
  const reason = [
    `osss kept ${count === 1 ? "a secret link" : `${count} secret links`} out of this conversation: your message was not sent to Claude.`,
    ...outcomes.map((o) => o.note),
    "",
    "Send this instead:",
    "",
    rewritten,
  ].join("\n");
  return { block: true, reason, rewritten };
}
