// The agent tool's protocol code (src/cli/client.ts) against the real Worker, so the tool and
// the browser can never drift apart.
import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { openSecret, revokeSecret, secretStatus, shareSecret } from "../src/cli/client";
import { CliError } from "../src/cli/errors";
import { Api } from "../src/cli/http";
import { parseReceiptLink, parseSecretLink } from "../src/cli/links";
import { b64urlDecode } from "../src/shared/encoding";
import worker from "../src/worker/index";
import { ORIGIN, freshIp, makeSecret } from "./helpers";

/** An Api whose requests go straight to the Worker, as one client IP, like Node's fetch would. */
function api(): Api {
  const ip = freshIp();
  return new Api(ORIGIN, async (url, init) => {
    const headers = new Headers(init.headers);
    headers.set("cf-connecting-ip", ip);
    // Node's fetch sends Content-Length for byte bodies; a Request built in workerd doesn't.
    if (init.body instanceof Uint8Array) headers.set("content-length", String(init.body.byteLength));
    const request = new Request(url, { ...init, headers, redirect: "manual" }) as Request<unknown, IncomingRequestCfProperties>;
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    const body = await response.arrayBuffer();
    await waitOnExecutionContext(ctx);
    return new Response(body, { status: response.status, headers: response.headers });
  });
}

const origins = [ORIGIN];

async function failure(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof CliError) return error;
    throw error;
  }
  throw new Error("expected a CliError");
}

describe("agent tool against the Worker", () => {
  it("shares and opens text exactly once", async () => {
    const shared = await shareSecret(api(), { text: "API_KEY=s3cr3t", file: null, views: 1, expiresIn: 3600, passphrase: null });
    expect(shared.link).toMatch(new RegExp(`^${ORIGIN}/s#[A-Za-z0-9_-]{43}$`));
    expect(shared.passphrase).toBeNull();

    const link = parseSecretLink(shared.link, origins);
    const opened = await openSecret(api(), link.S, null);
    expect(opened).toMatchObject({ text: "API_KEY=s3cr3t", file: null, viewsLeft: 0 });
    expect((await failure(openSecret(api(), link.S, null))).code).toBe("gone");
  });

  it("shares and opens an attached file", async () => {
    const data = new Uint8Array(70_000).map((_, i) => (i * 31) % 256);
    const shared = await shareSecret(api(), {
      text: "",
      file: { name: "../../keys‮.env", type: "", data },
      views: 2,
      expiresIn: 900,
      passphrase: null,
    });
    const S = parseSecretLink(shared.link, origins).S;
    const first = await openSecret(api(), S, null);
    expect(first.viewsLeft).toBe(1);
    expect(first.file?.data).toEqual(data);
    // No path separators, leading dots or bidi controls survive.
    expect(first.file?.name).toBe("_.._keys_.env");
    expect(first.file?.type).toBe("application/octet-stream");
    expect((await openSecret(api(), S, null)).viewsLeft).toBe(0);
  });

  it("asks for a passphrase without using a view or an attempt", async () => {
    const shared = await shareSecret(api(), { text: "behind a passphrase", file: null, views: 1, expiresIn: 3600, passphrase: true });
    expect(shared.passphrase).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
    const S = parseSecretLink(shared.link, origins).S;

    expect((await failure(openSecret(api(), S, null))).code).toBe("passphrase_required");
    expect((await failure(openSecret(api(), S, null))).code).toBe("passphrase_required");
    const wrong = await failure(openSecret(api(), S, "WRONG-WRONG"));
    expect(wrong.code).toBe("wrong_passphrase");
    expect(wrong.attemptsLeft).toBe(4);
    expect((await openSecret(api(), S, shared.passphrase)).text).toBe("behind a passphrase");
  });

  it("opens secrets made by the browser code", async () => {
    const made = await makeSecret({ text: "from the browser", maxViews: 2 });
    expect((await openSecret(api(), made.S, null)).text).toBe("from the browser");
  });

  it("reports unknown links as not found", async () => {
    expect((await failure(openSecret(api(), b64urlDecode("A".repeat(43)), null))).code).toBe("not_found");
  });

  it("shows receipts and revokes", async () => {
    const shared = await shareSecret(api(), { text: "to revoke", file: null, views: 3, expiresIn: 86400, passphrase: null });
    const receipt = parseReceiptLink(shared.receipt, origins);
    await openSecret(api(), parseSecretLink(shared.link, origins).S, null);

    const status = await secretStatus(api(), receipt);
    expect(status).toMatchObject({ state: "active", maxViews: 3, viewsLeft: 2 });
    expect(status.views).toHaveLength(1);

    expect((await revokeSecret(api(), receipt)).state).toBe("revoked");
    expect((await failure(openSecret(api(), parseSecretLink(shared.link, origins).S, null))).code).toBe("gone");
    expect((await failure(secretStatus(api(), { ...receipt, manageToken: "A".repeat(43) }))).code).toBe("not_found");
  });

  it("refuses text over the limit before sending anything", async () => {
    const error = await failure(shareSecret(api(), { text: "x".repeat(70_000), file: null, views: 1, expiresIn: 3600, passphrase: null }));
    expect(error.code).toBe("too_large");
  });
});
