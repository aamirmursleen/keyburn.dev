import { env } from "cloudflare:workers";
import { createExecutionContext, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import worker from "../src/worker/index";
import { describe, expect, it } from "vitest";
import { aad, openFile, openPayload, requesterKeys } from "../src/shared/crypto";
import { LIMITS } from "../src/shared/protocol";
import {
  ORIGIN,
  b64urlDecode,
  b64urlEncode,
  call,
  eventually,
  fileKeyOf,
  freshIp,
  makeRequest,
  makeSecret,
  makeSubmission,
  randomBytes,
  runAlarm,
  shiftTime,
  storedKeys,
  tokenHash,
  upload,
  vaultStub,
} from "./helpers";
import { Vault } from "../src/worker/vault";

const stored = async (key: string) => (await env.FILES.head(key)) !== null;
const deleted = (key: string) => eventually(async () => !(await stored(key)));

describe("encrypted file attachments", () => {
  it("uploads, downloads once and deletes the ciphertext", async () => {
    const data = randomBytes(5000);
    const secret = await makeSecret({ file: data });
    expect(secret.res.status).toBe(201);
    const uploadToken = secret.res.body.data.uploadToken as string;
    expect(uploadToken).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // Invisible to recipients until the upload completes.
    expect((await call("secret/meta", { id: secret.id, metaToken: secret.metaToken })).status).toBe(404);

    const up = await upload("secret", secret.id, uploadToken, secret.file!.ct);
    expect(up.status).toBe(200);
    const key = await fileKeyOf("secret", secret.id);
    expect(await stored(key)).toBe(true);
    // An upload token works only until the upload completes.
    expect((await upload("secret", secret.id, uploadToken, secret.file!.ct)).status).toBe(404);

    const meta = await call("secret/meta", { id: secret.id, metaToken: secret.metaToken });
    expect(meta.body.data.file).toEqual({ size: secret.file!.ct.length });

    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(opened.status).toBe(200);
    const payload = await openPayload(secret.textKey, aad.secretText(secret.id), opened.body.data);
    expect(payload.file).toEqual({ name: "keys.env", type: "text/plain", size: 5000 });
    const ticket = opened.body.data.file.ticket as string;

    const download = await call("secret/download", { id: secret.id, ticket });
    expect(download.status).toBe(200);
    expect(download.headers.get("content-type")).toBe("application/octet-stream");
    expect(download.headers.get("cache-control")).toBe("no-store");
    const plain = await openFile(secret.fileKey, aad.secretFile(secret.id), opened.body.data.file.iv, download.body, payload.file!.size);
    expect(plain).toEqual(data);

    // The completed download consumed the ticket and released the file.
    expect((await call("secret/download", { id: secret.id, ticket })).status).toBe(404);
    await runAlarm("secret", secret.id);
    await deleted(key);
    await eventually(async () => (await storedKeys("secret", secret.id)).join() === "tomb");
  });

  it("rejects uploads with a wrong token or size", async () => {
    const secret = await makeSecret({ file: randomBytes(2000) });
    const token = secret.res.body.data.uploadToken as string;
    expect((await upload("secret", secret.id, b64urlEncode(randomBytes(32)), secret.file!.ct)).status).toBe(404);
    expect((await upload("secret", secret.id, token, secret.file!.ct.subarray(0, 100))).status).toBe(400);
    const missingAuth = await call("upload", null, {
      method: "PUT",
      raw: secret.file!.ct,
      headers: { "content-type": "application/octet-stream", "x-vault-box": `secret:${secret.id}` },
    });
    expect(missingAuth.status).toBe(400);
    // The right upload still works afterwards.
    expect((await upload("secret", secret.id, token, secret.file!.ct)).status).toBe(200);
  });

  it("keeps exactly one intact copy when the same upload arrives twice at once", async () => {
    const data = randomBytes(8000);
    const secret = await makeSecret({ file: data });
    const token = secret.res.body.data.uploadToken as string;
    const [first, second] = await Promise.all([
      upload("secret", secret.id, token, secret.file!.ct),
      upload("secret", secret.id, token, secret.file!.ct),
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 404]);

    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    const download = await call("secret/download", { id: secret.id, ticket: opened.body.data.file.ticket });
    expect(download.status).toBe(200);
    const plain = await openFile(secret.fileKey, aad.secretFile(secret.id), opened.body.data.file.iv, download.body, data.length);
    expect(plain).toEqual(data);
  });

  it("abandons secrets whose upload never completes", async () => {
    const secret = await makeSecret({ file: randomBytes(1000) });
    await shiftTime("secret", secret.id, LIMITS.uploadWindowMs + 60_000);
    await runAlarm("secret", secret.id);
    const status = await call("secret/status", { id: secret.id, manageToken: secret.manageToken });
    expect(status.body.data.state).toBe("abandoned");
  });

  it("deletes the file immediately when the sender revokes", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const key = await fileKeyOf("secret", secret.id);
    expect(await stored(key)).toBe(true);
    await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
    await runAlarm("secret", secret.id);
    await deleted(key);
  });

  it("expires unused download tickets and then deletes the file", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const key = await fileKeyOf("secret", secret.id);
    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    await shiftTime("secret", secret.id, LIMITS.downloadTicketMs + 60_000);
    await runAlarm("secret", secret.id);
    expect((await call("secret/download", { id: secret.id, ticket: opened.body.data.file.ticket })).status).toBe(404);
    await deleted(key);
  });

  it("cuts off an in-flight download when the sender destroys an already-viewed secret", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const key = await fileKeyOf("secret", secret.id);
    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    expect(opened.body.data.viewsLeft).toBe(0);
    const revoked = await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
    expect(revoked.body.data.state).toBe("viewed");
    expect((await call("secret/download", { id: secret.id, ticket: opened.body.data.file.ticket })).status).toBe(404);
    await runAlarm("secret", secret.id);
    await deleted(key);
  });

  it("deletes a draining file when its ticket runs out of retries without a finished download", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const key = await fileKeyOf("secret", secret.id);
    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });
    const stub = vaultStub("secret", secret.id);
    const hash = await tokenHash(opened.body.data.file.ticket);
    // Three download attempts that never finish (e.g. dropped connections) use up the ticket.
    for (let i = 0; i < 3; i++) expect((await stub.redeemTicket(hash)).ok).toBe(true);

    const state = await runInDurableObject(stub, async (_v: Vault, s: DurableObjectState) => ({
      alarm: await s.storage.getAlarm(),
      until: s.storage.kv.get<{ tickets: { until: number }[] }>("file")!.tickets[0]!.until,
    }));
    // The next wake-up is the ticket's expiry, not the 30-day tombstone purge.
    expect(state.alarm).toBe(state.until);
    // Until then the last attempt may still be streaming, so other calls keep the file.
    await call("secret/status", { id: secret.id, manageToken: secret.manageToken });
    expect(await stored(key)).toBe(true);
    await shiftTime("secret", secret.id, LIMITS.downloadTicketMs + 60_000);
    await runAlarm("secret", secret.id);
    await deleted(key);
  });

  it("cuts off a download that is already streaming when the sender destroys the secret", async () => {
    const secret = await makeSecret({ file: randomBytes(8 * 1024 * 1024), maxViews: 2 });
    expect((await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct)).status).toBe(200);
    const opened = await call("secret/open", { id: secret.id, metaToken: secret.metaToken, readToken: secret.readToken });

    const ctx = createExecutionContext();
    const request = new Request(`${ORIGIN}/api/v1/secret/download`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": freshIp(), "sec-fetch-site": "same-origin" },
      body: JSON.stringify({ id: secret.id, ticket: opened.body.data.file.ticket }),
    }) as Request<unknown, IncomingRequestCfProperties>;
    const res = await worker.fetch(request, env, ctx);
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    let received = (await reader.read()).value?.byteLength ?? 0;

    expect((await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken })).status).toBe(200);
    const rest = (async () => {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) return;
        received += value.byteLength;
      }
    })();
    await expect(rest).rejects.toThrow();
    expect(received).toBeLessThan(secret.file!.ct.length);
    await waitOnExecutionContext(ctx);
  });

  it("exposes only the capability-checked methods over RPC", () => {
    // Workers RPC dispatches prototype methods; #private helpers are not among them.
    const methods = Object.getOwnPropertyNames(Vault.prototype);
    for (const helper of ["get", "put", "drop", "queueDelete", "dropFile", "destroy", "reconcile", "schedule", "finish", "inboxOf"]) {
      expect(methods).not.toContain(helper);
    }
    expect(methods).toEqual(expect.arrayContaining(["openSecret", "redeemTicket", "downloadAllowed", "alarm"]));
  });

  it("cuts off a request download when the requester cancels after opening", async () => {
    const req = await makeRequest();
    const { input, sealedFile } = await makeSubmission(req, "see attached", randomBytes(4096));
    const submitted = await call("request/submit", input);
    await upload("request", req.id, submitted.body.data.uploadToken, sealedFile!.ct);
    const key = await fileKeyOf("request", req.id);
    const opened = await call("request/open", { id: req.id, inboxToken: req.inboxToken });
    expect(opened.status).toBe(200);
    expect((await call("request/revoke", { id: req.id, inboxToken: req.inboxToken })).status).toBe(200);
    expect((await call("request/download", { id: req.id, ticket: opened.body.data.file.ticket })).status).toBe(404);
    await runAlarm("request", req.id);
    await deleted(key);
  });

  it("keeps a key queued when it is queued again while its deletion is in flight", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const key = await fileKeyOf("secret", secret.id);
    await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });

    // Hold the first R2 batch delete open until the test releases it.
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    let calls = 0;
    let restore: () => void = () => {};
    const stub = vaultStub("secret", secret.id);
    await runInDurableObject(stub, (instance: Vault) => {
      const files = (instance as unknown as { env: Env }).env.FILES;
      const original = files.delete.bind(files);
      Object.defineProperty(files, "delete", {
        configurable: true,
        writable: true,
        value: async (keys: string | string[]) => {
          calls++;
          if (calls === 1) await gate;
          return original(keys);
        },
      });
      restore = () => Object.defineProperty(files, "delete", { configurable: true, writable: true, value: original });
    });

    try {
      const firstBatch = runAlarm("secret", secret.id);
      await eventually(async () => calls === 1);
      // e.g. an upload attempt that landed after the delete ran is discarded again.
      await stub.abortUpload(key);
      release();
      await firstBatch;
      const queued = await runInDurableObject(stub, (_v: Vault, s: DurableObjectState) => s.storage.kv.get<string[]>("r2del"));
      expect(queued).toEqual([key]);
      await runAlarm("secret", secret.id);
      await deleted(key);
      // The retry alarm is due immediately, so the runtime may also fire it on its own; wait
      // for whichever run is in flight to finish clearing the queue.
      await eventually(async () => (await runInDurableObject(stub, (_v: Vault, s: DurableObjectState) => s.storage.kv.get("r2del"))) === undefined);
    } finally {
      restore();
    }
  });

  it("caps the total number of upload attempts per file", async () => {
    const secret = await makeSecret({ file: randomBytes(2000) });
    const token = secret.res.body.data.uploadToken as string;
    const ct = secret.file!.ct;
    // An attempt that declares the right length but sends too few bytes starts, fails and
    // queues its own object for deletion, so attempts must be bounded in total.
    const truncated = () =>
      call("upload", null, {
        method: "PUT",
        raw: ct.subarray(0, 100),
        headers: {
          "content-type": "application/octet-stream",
          "content-length": String(ct.length),
          "x-vault-box": `secret:${secret.id}`,
          authorization: `Bearer ${token}`,
        },
      });
    for (let i = 0; i < 20; i++) expect((await truncated()).status).toBe(400);
    expect((await upload("secret", secret.id, token, ct)).status).toBe(409);
  });

  it("deletes a long queue in bounded batches and then purges the tombstone", async () => {
    const secret = await makeSecret();
    await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
    const stub = vaultStub("secret", secret.id);
    const batches: number[] = [];
    let restore: () => void = () => {};
    await runInDurableObject(stub, (instance: Vault, state: DurableObjectState) => {
      state.storage.kv.put("r2del", Array.from({ length: 250 }, (_, i) => `v1/queued-${i}`));
      const files = (instance as unknown as { env: Env }).env.FILES;
      const original = files.delete.bind(files);
      Object.defineProperty(files, "delete", {
        configurable: true,
        writable: true,
        value: async (keys: string | string[]) => {
          batches.push(Array.isArray(keys) ? keys.length : 1);
          return original(keys);
        },
      });
      restore = () => Object.defineProperty(files, "delete", { configurable: true, writable: true, value: original });
    });
    try {
      await shiftTime("secret", secret.id, LIMITS.tombstoneRetentionMs + 60_000);
      await eventually(async () => {
        await runAlarm("secret", secret.id);
        return (await storedKeys("secret", secret.id)).join() === "burned";
      });
      expect(batches.length).toBeGreaterThanOrEqual(3);
      expect(Math.max(...batches)).toBeLessThanOrEqual(100);
    } finally {
      restore();
    }
  });

  it("keeps the retry back-off after a failed deletion even when requests arrive", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const stub = vaultStub("secret", secret.id);
    let restore: () => void = () => {};
    await runInDurableObject(stub, (instance: Vault) => {
      const files = (instance as unknown as { env: Env }).env.FILES;
      const original = files.delete.bind(files);
      Object.defineProperty(files, "delete", {
        configurable: true,
        writable: true,
        value: async () => {
          throw new Error("R2 unavailable");
        },
      });
      restore = () => Object.defineProperty(files, "delete", { configurable: true, writable: true, value: original });
    });
    try {
      await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
      await runAlarm("secret", secret.id);
      // Another request reschedules the object, but must not pull the retry forward.
      await call("secret/status", { id: secret.id, manageToken: secret.manageToken });
      const alarm = await runInDurableObject(stub, (_v: Vault, s: DurableObjectState) => s.storage.getAlarm());
      expect(alarm).toBeGreaterThan(Date.now() + 50_000);
    } finally {
      restore();
    }
  });

  it("retries R2 deletion until it succeeds", async () => {
    const secret = await makeSecret({ file: randomBytes(3000) });
    await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct);
    const key = await fileKeyOf("secret", secret.id);

    // Make the vault's own R2 binding fail exactly once.
    let failures = 0;
    let restore: () => void = () => {};
    await runInDurableObject(vaultStub("secret", secret.id), (instance: Vault) => {
      const files = (instance as unknown as { env: Env }).env.FILES;
      const original = files.delete.bind(files);
      Object.defineProperty(files, "delete", {
        configurable: true,
        writable: true,
        value: async (keys: string | string[]) => {
          if (failures === 0) {
            failures++;
            throw new Error("R2 unavailable");
          }
          return original(keys);
        },
      });
      restore = () => Object.defineProperty(files, "delete", { configurable: true, writable: true, value: original });
    });

    try {
      await call("secret/revoke", { id: secret.id, manageToken: secret.manageToken });
      await eventually(async () => {
        await runAlarm("secret", secret.id);
        return failures === 1;
      });
      // The first deletion failed, yet the object still disappears: the alarm retried it.
      await runAlarm("secret", secret.id);
      await deleted(key);
      expect(failures).toBe(1);
    } finally {
      restore();
    }
  });

  it("carries files in request submissions", async () => {
    const req = await makeRequest();
    const data = randomBytes(4096);
    const { input, sealedFile } = await makeSubmission(req, "see attached", data);
    const submitted = await call("request/submit", input);
    expect(submitted.status).toBe(201);
    const token = submitted.body.data.uploadToken as string;

    expect((await call("request/status", { id: req.id, inboxToken: req.inboxToken })).body.data.state).toBe("receiving");
    expect((await call("request/open", { id: req.id, inboxToken: req.inboxToken })).status).toBe(409);

    expect((await upload("request", req.id, token, sealedFile!.ct)).status).toBe(200);
    const status = await call("request/status", { id: req.id, inboxToken: req.inboxToken });
    expect(status.body.data).toMatchObject({ state: "received", file: { size: sealedFile!.ct.length } });

    const opened = await call("request/open", { id: req.id, inboxToken: req.inboxToken });
    const keys = await requesterKeys(req.pub, req.d, req.Q, req.id, b64urlDecode(opened.body.data.ephPub));
    const payload = await openPayload(keys.textKey, aad.requestText(req.id), opened.body.data);
    const download = await call("request/download", { id: req.id, ticket: opened.body.data.file.ticket });
    const plain = await openFile(keys.fileKey, aad.requestFile(req.id), opened.body.data.file.iv, download.body, payload.file!.size);
    expect(plain).toEqual(data);
  });

  it("reopens a request when the submitter's upload is abandoned", async () => {
    const req = await makeRequest();
    const { input } = await makeSubmission(req, "file never arrives", randomBytes(2048));
    await call("request/submit", input);
    await shiftTime("request", req.id, LIMITS.uploadWindowMs + 60_000);
    await runAlarm("request", req.id);
    expect((await call("request/status", { id: req.id, inboxToken: req.inboxToken })).body.data.state).toBe("waiting");
    expect((await call("request/info", { id: req.id, submitToken: req.submitToken })).body.data.state).toBe("open");
  });
});
