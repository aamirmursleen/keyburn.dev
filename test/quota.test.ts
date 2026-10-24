import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { clientKey, hashClient, networkKey } from "../src/worker/ip";
import { Quota, quotaName } from "../src/worker/quota";
import { call, eventually, freshIp, makeRequest, makeSecret, randomBytes, runAlarm, upload } from "./helpers";
import { encodedSize } from "../src/worker/validate";

function quotaStub(name: string) {
  const ns = env.QUOTA as unknown as DurableObjectNamespace<Quota>;
  return ns.get(ns.idFromName(name));
}

const today = () => new Date().toISOString().slice(0, 10);

async function fill(name: string, creates: number, bytes: number) {
  await runInDurableObject(quotaStub(name), (_q: Quota, state: DurableObjectState) => {
    state.storage.kv.put("used", { creates, bytes });
  });
}

describe("client keys", () => {
  const req = (ip: string) => new Request("https://x", { headers: { "cf-connecting-ip": ip } });

  it("groups IPv6 clients by /64 and keeps IPv4 as-is", () => {
    expect(clientKey(req("2001:db8:1:2:aaaa::1"))).toBe(clientKey(req("2001:db8:1:2:bbbb:cccc:dddd:eeee")));
    expect(clientKey(req("2001:db8:1:3::1"))).not.toBe(clientKey(req("2001:db8:1:2::1")));
    expect(clientKey(req("::ffff:192.0.2.1"))).toBe("192.0.2.1");
    expect(clientKey(req("192.0.2.1"))).toBe("192.0.2.1");
    expect(clientKey(req("not an ip"))).toBe("invalid");
    expect(clientKey(new Request("https://x"))).toBe("unknown");
  });

  it("groups IPv6 networks by /48 and has no network for IPv4", () => {
    expect(networkKey(req("2001:db8:1:2::1"))).toBe("2001:db8:1::/48");
    expect(networkKey(req("2001:db8:1:ffff:aaaa::1"))).toBe(networkKey(req("2001:db8:1:2::1")));
    expect(networkKey(req("2001:db8:2:2::1"))).not.toBe(networkKey(req("2001:db8:1:2::1")));
    expect(networkKey(req("192.0.2.1"))).toBeNull();
    expect(networkKey(req("::ffff:192.0.2.1"))).toBeNull();
    expect(networkKey(req("not an ip"))).toBeNull();
    expect(networkKey(new Request("https://x"))).toBeNull();
  });

  it("hashes client keys with a server secret", async () => {
    const a = await hashClient("secret-a", "192.0.2.1");
    expect(a).toBe(await hashClient("secret-a", "192.0.2.1"));
    expect(a).not.toBe(await hashClient("secret-b", "192.0.2.1"));
    expect(a).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });
});

describe("daily quotas", () => {
  it("blocks a client that used up its daily creations", async () => {
    const ip = freshIp();
    const mac = await hashClient(env.IP_HASH_SECRET, ip);
    await fill(quotaName("ip", mac, today()), Number(env.QUOTA_IP_CREATES_PER_DAY), 0);
    const blocked = await makeSecret({ ip });
    expect(blocked.res.status).toBe(429);
    expect(blocked.res.body).toEqual({ success: false, error: "quota_exceeded" });
    // Other clients are unaffected.
    expect((await makeSecret()).res.status).toBe(201);
  });

  it("makes every /64 in one IPv6 /48 share the network's daily budget", async () => {
    const net = await hashClient(env.IP_HASH_SECRET, "2001:db8:aa::/48");
    await fill(quotaName("net", net, today()), Number(env.QUOTA_NET_CREATES_PER_DAY), 0);
    // Fresh /64s inside the same /48 are refused, and their own charge is refunded.
    expect((await makeSecret({ ip: "2001:db8:aa:1::1" })).res.status).toBe(429);
    expect((await makeSecret({ ip: "2001:db8:aa:2::1" })).res.status).toBe(429);
    const mine = await hashClient(env.IP_HASH_SECRET, "2001:db8:aa:1::/64");
    const usage = await runInDurableObject(quotaStub(quotaName("ip", mine, today())), (_q: Quota, s: DurableObjectState) =>
      s.storage.kv.get("used"),
    );
    expect(usage).toEqual({ creates: 0, bytes: 0 });
    // Other networks are unaffected.
    expect((await makeSecret({ ip: "2001:db8:bb:1::1" })).res.status).toBe(201);
  });

  it("enforces the global byte budget and refunds the client", async () => {
    const ip = freshIp();
    const mac = await hashClient(env.IP_HASH_SECRET, ip);
    const global = quotaName("global", "all", today());
    await fill(global, 0, Number(env.QUOTA_GLOBAL_BYTES_PER_DAY));

    const blocked = await makeSecret({ ip });
    expect(blocked.res.status).toBe(429);
    // Users are told the service is at capacity, not that their own network is.
    expect(blocked.res.body).toEqual({ success: false, error: "capacity" });
    const ipUsage = await runInDurableObject(quotaStub(quotaName("ip", mac, today())), (_q: Quota, s: DurableObjectState) =>
      s.storage.kv.get("used"),
    );
    expect(ipUsage).toEqual({ creates: 0, bytes: 0 });

    // Requests count against the same budgets.
    expect((await makeRequest()).res.status).toBe(429);
    await fill(global, 0, 0);
    expect((await makeSecret({ ip })).res.status).toBe(201);
  });

  it("charges file bytes only when the upload actually succeeds", async () => {
    const ip = freshIp();
    const mac = await hashClient(env.IP_HASH_SECRET, ip);
    const usage = () => runInDurableObject(quotaStub(quotaName("ip", mac, today())), (_q: Quota, s: DurableObjectState) =>
      s.storage.kv.get<{ creates: number; bytes: number }>("used"),
    );
    const secret = await makeSecret({ ip, file: randomBytes(50_000) });
    const inline = encodedSize(secret.input.ct) + 1024;
    expect(await usage()).toEqual({ creates: 1, bytes: inline });

    // A failed creation (duplicate id) is refunded.
    expect((await call("secret/create", secret.input, { ip })).status).toBe(409);
    expect(await usage()).toEqual({ creates: 1, bytes: inline });

    expect((await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct, ip)).status).toBe(200);
    expect(await usage()).toEqual({ creates: 1, bytes: inline + secret.file!.ct.length });
  });

  it("rejects uploads that would exceed the byte budget and deletes what arrived", async () => {
    const ip = freshIp();
    const mac = await hashClient(env.IP_HASH_SECRET, ip);
    const secret = await makeSecret({ ip, file: randomBytes(20_000) });
    const name = quotaName("ip", mac, today());
    const limit = Number(env.QUOTA_IP_BYTES_PER_DAY);
    await fill(name, 1, limit - 100);
    const keys = async () => (await env.FILES.list()).objects.map((o) => o.key).sort().join();
    const before = await keys();
    const res = await upload("secret", secret.id, secret.res.body.data.uploadToken, secret.file!.ct, ip);
    expect(res.status).toBe(429);
    const after = await runInDurableObject(quotaStub(name), (_q: Quota, s: DurableObjectState) => s.storage.kv.get("used"));
    expect(after).toEqual({ creates: 1, bytes: limit - 100 });
    expect((await call("secret/meta", { id: secret.id, metaToken: secret.metaToken })).status).toBe(404);

    // Bytes are charged only after they arrive; the refused attempt's object is then deleted.
    await eventually(async () => {
      await runAlarm("secret", secret.id);
      return (await keys()) === before;
    });
  });

  it("refunds the client's charge when the global counter fails", async () => {
    const ip = freshIp();
    const mac = await hashClient(env.IP_HASH_SECRET, ip);
    // Only the global counter fails; the client's own counter works normally.
    const globalId = env.QUOTA.idFromName(quotaName("global", "all", today()));
    const original = Quota.prototype.consume;
    Quota.prototype.consume = async function (this: Quota, ...args: Parameters<Quota["consume"]>) {
      if ((this as unknown as { ctx: DurableObjectState }).ctx.id.equals(globalId)) throw new Error("global counter unavailable");
      return original.apply(this, args);
    };
    try {
      expect((await makeSecret({ ip })).res.status).toBe(500);
    } finally {
      Quota.prototype.consume = original;
    }
    const usage = await runInDurableObject(quotaStub(quotaName("ip", mac, today())), (_q: Quota, s: DurableObjectState) =>
      s.storage.kv.get("used"),
    );
    expect(usage).toEqual({ creates: 0, bytes: 0 });
  });

  it("rejects amounts and limits that could disable the counter", async () => {
    await runInDurableObject(quotaStub(quotaName("ip", "bad-amounts", today())), async (quota: Quota) => {
      for (const [creates, bytes] of [[Number.NaN, 0], [0, -1], [0.5, 0], [0, Number.POSITIVE_INFINITY]]) {
        await expect(quota.consume(creates!, bytes!, { creates: 5, bytes: 100 })).rejects.toThrow(RangeError);
        expect(() => quota.refund(creates!, bytes!)).toThrow(RangeError);
      }
      await expect(quota.consume(1, 1, { creates: Number.NaN, bytes: 100 })).rejects.toThrow(RangeError);
      expect(await quota.consume(1, 10, { creates: 5, bytes: 100 })).toBe(true);
    });
  });

  it("deletes itself after the day ends", async () => {
    const name = quotaName("ip", "cleanup-test", today());
    const stub = quotaStub(name);
    expect(await stub.consume(1, 10, { creates: 5, bytes: 100 })).toBe(true);
    await runInDurableObject(stub, async (q: Quota) => {
      await q.alarm();
    });
    const left = await runInDurableObject(stub, (_q: Quota, s: DurableObjectState) => [...s.storage.kv.list()].length);
    expect(left).toBe(0);
  });
});
