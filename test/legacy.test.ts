import { describe, expect, it } from "vitest";
import { lookupWithLegacyId } from "../src/shared/legacy";

type Res = { ok: true; data: string } | { ok: false; error: string };
const ids = { id: "new", legacyId: "old" };

function fake(records: Record<string, Res>) {
  const seen: string[] = [];
  const lookup = async (id: string): Promise<Res> => {
    seen.push(id);
    return records[id] ?? { ok: false, error: "not_found" };
  };
  return { seen, lookup };
}

describe("legacy id fallback", () => {
  it("uses the current id when the record exists", async () => {
    const { seen, lookup } = fake({ new: { ok: true, data: "x" } });
    expect(await lookupWithLegacyId(ids, lookup)).toEqual({ id: "new", res: { ok: true, data: "x" } });
    expect(seen).toEqual(["new"]);
  });

  it("falls back to the older id only when the current one is not found", async () => {
    const { seen, lookup } = fake({ old: { ok: true, data: "legacy" } });
    expect(await lookupWithLegacyId(ids, lookup)).toEqual({ id: "old", res: { ok: true, data: "legacy" } });
    expect(seen).toEqual(["new", "old"]);
  });

  it("reports the original failure when neither id exists", async () => {
    const { lookup } = fake({});
    expect(await lookupWithLegacyId(ids, lookup)).toEqual({ id: "new", res: { ok: false, error: "not_found" } });
  });

  it("does not retry on other errors or once the id is resolved", async () => {
    const network = fake({ new: { ok: false, error: "network" } });
    expect((await lookupWithLegacyId(ids, network.lookup)).res).toEqual({ ok: false, error: "network" });
    expect(network.seen).toEqual(["new"]);
    const resolved = fake({});
    await lookupWithLegacyId({ id: "old", legacyId: "old" }, resolved.lookup);
    expect(resolved.seen).toEqual(["old"]);
  });
});
