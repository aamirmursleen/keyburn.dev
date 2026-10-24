// WebMCP (https://webmachinelearning.github.io/webmcp/): lets an AI agent working in this browser
// tab create a secret link with the page's own encryption. There is deliberately no tool for
// opening secrets: an agent should never see a secret's value (agents use the local osss tool
// for that, see /agents).

import { SECRET_EXPIRY_SECONDS, VIEW_CHOICES } from "../shared/protocol";

export interface AgentShareInput {
  text: string;
  expiresIn: (typeof SECRET_EXPIRY_SECONDS)[number];
  maxViews: (typeof VIEW_CHOICES)[number];
  passphrase: boolean;
}

export type AgentShareResult =
  | { ok: true; link: string; receipt: string; expiresAt: number; passphrase: string | null }
  | { ok: false; message: string };

interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

interface ModelContext {
  registerTool(
    tool: {
      name: string;
      title?: string;
      description: string;
      inputSchema: object;
      annotations?: { readOnlyHint?: boolean };
      execute: (input: unknown) => Promise<ToolResult>;
    },
    options?: { signal?: AbortSignal },
  ): unknown;
}

const EXPIRY: Record<string, (typeof SECRET_EXPIRY_SECONDS)[number]> = { "15m": 900, "1h": 3600, "1d": 86400, "3d": 259200, "7d": 604800 };
const MAX_TEXT = 64 * 1024;

function result(data: unknown, isError = false): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(data) }], ...(isError ? { isError: true } : {}) };
}

function parse(input: unknown): AgentShareInput | null {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return null;
  const o = input as Record<string, unknown>;
  if (Object.keys(o).some((k) => !["text", "views", "expiresIn", "passphrase"].includes(k))) return null;
  const views = o.views ?? 1;
  const expires = o.expiresIn ?? "1d";
  if (typeof o.text !== "string" || o.text.length === 0 || o.text.length > MAX_TEXT) return null;
  if (!(VIEW_CHOICES as readonly unknown[]).includes(views) || typeof expires !== "string" || !(expires in EXPIRY)) return null;
  if (o.passphrase !== undefined && typeof o.passphrase !== "boolean") return null;
  return {
    text: o.text,
    maxViews: views as AgentShareInput["maxViews"],
    expiresIn: EXPIRY[expires] as AgentShareInput["expiresIn"],
    passphrase: o.passphrase === true,
  };
}

/** Registers the create tool when the browser supports WebMCP; does nothing otherwise. */
export function registerCreateTool(create: (input: AgentShareInput) => Promise<AgentShareResult>): void {
  const holder = document as Document & { modelContext?: ModelContext };
  const context = holder.modelContext ?? (navigator as Navigator & { modelContext?: ModelContext }).modelContext;
  if (!context || typeof context.registerTool !== "function") return;
  try {
    void Promise.resolve(
      context.registerTool({
        name: "create_secret_link",
        title: "Create a self-destructing secret link",
        description:
          "Encrypts text in this page (the key stays in the link and never reaches the server) and returns a link that self-destructs after its views or when it expires, plus a private receipt link for the sender. Give the link only to the intended recipient, and send a passphrase, if any, a different way.",
        inputSchema: {
          type: "object",
          properties: {
            text: { type: "string", minLength: 1, maxLength: MAX_TEXT, description: "The secret to share." },
            views: { type: "integer", enum: [...VIEW_CHOICES], default: 1, description: "How many times it can be opened." },
            expiresIn: { type: "string", enum: Object.keys(EXPIRY), default: "1d", description: "When it expires if not used up." },
            passphrase: { type: "boolean", default: false, description: "Also require a generated passphrase, returned separately." },
          },
          required: ["text"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: false },
        async execute(input: unknown): Promise<ToolResult> {
          const parsed = parse(input);
          if (!parsed) return result({ error: "invalid_input", message: "Give text (up to 64 KB), views 1/2/3/5/10, expiresIn 15m/1h/1d/3d/7d." }, true);
          const shared = await create(parsed);
          if (!shared.ok) return result({ error: "failed", message: shared.message }, true);
          return result({
            link: shared.link,
            receipt: shared.receipt,
            expiresAt: new Date(shared.expiresAt).toISOString(),
            passphrase: shared.passphrase,
          });
        },
      }),
    ).catch(() => undefined);
  } catch {
    // An older or different WebMCP implementation: the page works the same without it.
  }
}
