import { createHash, timingSafeEqual } from "node:crypto";

/**
 * DEVELOPMENT PLACEHOLDER for the human's sign-in on the OAuth consent page (same status as the owner-key login in
 * DIAPORIA Agent Commerce PR #9). It identifies WHICH SafeBox account an AI client may read/prepare for. It is NOT an
 * owner approval: no secret entered here can sign, approve or settle a payment. Production needs a real identity
 * provider; payment approval always needs the enrolled SafeBox device.
 */
export class AccountDirectory {
  private readonly users: Array<{ hash: Buffer; userId: string; accountRef: string }> = [];
  add(loginSecret: string, userId: string, accountRef: string) {
    if (loginSecret.length < 24) throw new Error("login secrets must be at least 24 characters");
    this.users.push({ hash: createHash("sha256").update(loginSecret).digest(), userId, accountRef });
  }
  verify(loginSecret: string | null | undefined): { userId: string; accountRef: string } | null {
    if (!loginSecret || loginSecret.length > 200) return null;
    const h = createHash("sha256").update(loginSecret).digest();
    let hit: { userId: string; accountRef: string } | null = null;
    for (const u of this.users) if (timingSafeEqual(u.hash, h)) hit = { userId: u.userId, accountRef: u.accountRef };
    return hit;
  }
  accountOf(userId: string): string | null { return this.users.find((u) => u.userId === userId)?.accountRef ?? null; }
}
