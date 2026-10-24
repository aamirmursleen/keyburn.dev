import { describe, expect, it } from "vitest";
import { aad, openPayload, requesterKeys } from "../src/shared/crypto";
import { LIMITS } from "../src/shared/protocol";
import {
  b64urlDecode,
  b64urlEncode,
  call,
  makeRequest,
  makeSubmission,
  randomBytes,
  runAlarm,
  shiftTime,
  storedKeys,
} from "./helpers";

const DAY = 86_400_000;

describe("request-a-secret flow", () => {
  it("lets the client submit once and only the requester open it once", async () => {
    const req = await makeRequest({ note: "WordPress admin for acme.com please" });
    expect(req.res.status).toBe(201);

    const info = await call("request/info", { id: req.id, submitToken: req.submitToken });
    expect(info.status).toBe(200);
    expect(info.body.data.state).toBe("open");
    const note = await openPayload(req.noteKey, aad.requestNote(req.id), info.body.data.note);
    expect(note.text).toBe("WordPress admin for acme.com please");

    const waiting = await call("request/status", { id: req.id, inboxToken: req.inboxToken });
    expect(waiting.body.data).toMatchObject({ state: "waiting", submittedAt: null, pub: req.input.pub });

    const { input } = await makeSubmission(req, "admin / correct-horse-battery");
    const submitted = await call("request/submit", input, { headers: { "cf-ipcountry": "GB" } });
    expect(submitted.status).toBe(201);
    expect(submitted.body.data.uploadToken).toBeNull();

    // The client link can no longer submit or see anything.
    const closed = await call("request/info", { id: req.id, submitToken: req.submitToken });
    expect(closed.body.data).toEqual({ state: "closed", reason: "submitted" });
    expect((await call("request/submit", input)).status).toBe(409);

    const received = await call("request/status", { id: req.id, inboxToken: req.inboxToken });
    expect(received.body.data.state).toBe("received");
    expect(received.body.data.submittedAt).toBeGreaterThan(0);
    expect(received.body.data.country).toBe("GB");
    // Retention restarts at submission so the requester has a week to open it.
    expect(received.body.data.expiresAt).toBeGreaterThan(Date.now() + LIMITS.submissionRetentionMs - 60_000);

    const opened = await call("request/open", { id: req.id, inboxToken: req.inboxToken });
    expect(opened.status).toBe(200);
    const keys = await requesterKeys(req.pub, req.d, req.Q, req.id, b64urlDecode(opened.body.data.ephPub));
    const payload = await openPayload(keys.textKey, aad.requestText(req.id), opened.body.data);
    expect(payload.text).toBe("admin / correct-horse-battery");

    expect((await call("request/open", { id: req.id, inboxToken: req.inboxToken })).status).toBe(404);
    const clientView = await call("request/info", { id: req.id, submitToken: req.submitToken });
    expect(clientView.body.data).toEqual({ state: "closed", reason: "submitted" });
    const after = await call("request/status", { id: req.id, inboxToken: req.inboxToken });
    expect(after.body.data.state).toBe("opened");
    expect(await storedKeys("request", req.id)).toEqual(["tomb"]);
  });

  it("rejects request ids that are not bound to the submit token", async () => {
    const req = await makeRequest();
    const probe = { ...req.input, submitHash: b64urlEncode(randomBytes(32)) };
    expect((await call("request/create", probe)).status).toBe(400);
    expect((await call("request/create", { ...probe, id: b64urlEncode(randomBytes(16)) })).status).toBe(400);
  });

  it("never lets anyone create a purged request id again", async () => {
    const req = await makeRequest({ note: "original note" });
    expect((await call("request/revoke", { id: req.id, inboxToken: req.inboxToken })).status).toBe(200);
    await shiftTime("request", req.id, LIMITS.tombstoneRetentionMs + DAY);
    await runAlarm("request", req.id);
    expect(await storedKeys("request", req.id)).toEqual(["burned"]);
    // A client-link holder can rebuild the id and submit hash, but the id stays taken.
    expect((await call("request/create", req.input)).status).toBe(409);
    expect((await call("request/info", { id: req.id, submitToken: req.submitToken })).status).toBe(404);
  });

  it("has nothing to open before a submission arrives", async () => {
    const req = await makeRequest();
    const early = await call("request/open", { id: req.id, inboxToken: req.inboxToken });
    expect(early.status).toBe(409);
  });

  it("keeps the submit and inbox capabilities separate", async () => {
    const req = await makeRequest();
    // The submit token cannot read the inbox and vice versa.
    expect((await call("request/status", { id: req.id, inboxToken: req.submitToken })).status).toBe(404);
    expect((await call("request/info", { id: req.id, submitToken: req.inboxToken })).status).toBe(404);
    expect((await call("request/info", { id: req.id, submitToken: b64urlEncode(randomBytes(32)) })).status).toBe(404);
  });

  it("lets the requester cancel a request", async () => {
    const req = await makeRequest();
    const revoked = await call("request/revoke", { id: req.id, inboxToken: req.inboxToken });
    expect(revoked.status).toBe(200);
    expect(revoked.body.data.state).toBe("revoked");
    const info = await call("request/info", { id: req.id, submitToken: req.submitToken });
    expect(info.body.data).toEqual({ state: "closed", reason: "revoked" });
    const { input } = await makeSubmission(req, "too late");
    expect((await call("request/submit", input)).status).toBe(404);
  });

  it("expires unanswered requests", async () => {
    const req = await makeRequest({ expiresIn: 3600 });
    await shiftTime("request", req.id, 2 * 3600_000);
    await runAlarm("request", req.id);
    const info = await call("request/info", { id: req.id, submitToken: req.submitToken });
    expect(info.body.data).toEqual({ state: "closed", reason: "expired" });
    const status = await call("request/status", { id: req.id, inboxToken: req.inboxToken });
    expect(status.body.data.state).toBe("expired");
  });

  it("expires unopened submissions after the retention window", async () => {
    const req = await makeRequest();
    const { input } = await makeSubmission(req, "secret");
    await call("request/submit", input);
    await shiftTime("request", req.id, LIMITS.submissionRetentionMs + DAY);
    await runAlarm("request", req.id);
    expect((await call("request/status", { id: req.id, inboxToken: req.inboxToken })).body.data.state).toBe("expired");
  });

  it("validates request creation", async () => {
    const req = await makeRequest();
    const base = { ...req.input };
    const badPub = randomBytes(65);
    badPub[0] = 2;
    for (const body of [
      { ...base, pub: b64urlEncode(badPub) },
      { ...base, pub: b64urlEncode(randomBytes(33)) },
      { ...base, expiresIn: 900 },
      { ...base, note: { iv: b64urlEncode(randomBytes(12)), ct: b64urlEncode(randomBytes(LIMITS.noteMaxFrameBytes * 2 + 16)) } },
    ]) {
      expect((await call("request/create", body)).status).toBe(400);
    }
    expect((await call("request/create", req.input)).status).toBe(409);
  });
});
