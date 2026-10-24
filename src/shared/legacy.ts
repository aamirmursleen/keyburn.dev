/**
 * Links created before record ids were bound to a capability (before 2026-10-24) still
 * address their records by the older id. A lookup tries the current id first and falls back
 * to the older one only when the record is not found. Remove after 2026-12-01, by when every
 * such record has expired and been purged.
 */
export async function lookupWithLegacyId<R extends { ok: boolean; error?: string }>(
  ids: { id: string; legacyId: string },
  lookup: (id: string) => Promise<R>,
): Promise<{ id: string; res: R }> {
  const res = await lookup(ids.id);
  if (res.ok || res.error !== "not_found" || ids.legacyId === ids.id) return { id: ids.id, res };
  const legacy = await lookup(ids.legacyId);
  return legacy.ok ? { id: ids.legacyId, res: legacy } : { id: ids.id, res };
}
