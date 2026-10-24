import { DurableObject } from "cloudflare:workers";

export interface QuotaLimits {
  creates: number;
  bytes: number;
}

interface Usage {
  creates: number;
  bytes: number;
}

const HOUR = 3_600_000;

export function quotaName(scope: "ip" | "net" | "global", key: string, day: string): string {
  return `${scope}:${key}:${day}`;
}

/** Amounts are non-negative whole numbers, so a bad value (e.g. NaN) can never disable the counter. */
function assertAmounts(...values: number[]): void {
  if (!values.every((n) => Number.isSafeInteger(n) && n >= 0)) throw new RangeError("Invalid quota amount");
}

function endOfUtcDay(now: number): number {
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1);
}

/**
 * Strict daily counter (one object per client per day, plus one global).
 * Check-and-increment is synchronous, so concurrent calls cannot overshoot.
 */
export class Quota extends DurableObject<Env> {
  async consume(creates: number, bytes: number, limits: QuotaLimits): Promise<boolean> {
    assertAmounts(creates, bytes);
    if (![limits.creates, limits.bytes].every((n) => Number.isFinite(n) && n >= 0)) throw new RangeError("Invalid quota limit");
    const used = this.ctx.storage.kv.get<Usage>("used") ?? { creates: 0, bytes: 0 };
    if (used.creates + creates > limits.creates || used.bytes + bytes > limits.bytes) return false;
    this.ctx.storage.kv.put("used", { creates: used.creates + creates, bytes: used.bytes + bytes });
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(endOfUtcDay(Date.now()) + HOUR);
    }
    return true;
  }

  refund(creates: number, bytes: number): void {
    assertAmounts(creates, bytes);
    const used = this.ctx.storage.kv.get<Usage>("used");
    if (!used) return;
    this.ctx.storage.kv.put("used", {
      creates: Math.max(0, used.creates - creates),
      bytes: Math.max(0, used.bytes - bytes),
    });
  }

  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
