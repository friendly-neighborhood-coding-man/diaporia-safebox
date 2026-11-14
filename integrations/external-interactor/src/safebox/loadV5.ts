/**
 * Loads the EXISTING SafeBox V5 modules (unchanged, plain .mjs) from the repository root.
 *
 * The integration package never edits or re-implements Root, Vault, Risk Engine, ownership or signing code; it imports
 * the frozen modules read-only. Only the narrow, typed surface below is used by the service adapter. The owner world
 * (simulated devices and their signers) is loaded ONLY by the mock harness (tests/ and scripts/), never by src/.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** Directory of the diaporia-safebox repository (the one that contains src/v5). */
export function safeboxRoot(): string {
  const env = process.env.SAFEBOX_REPO_ROOT;
  if (env) return resolve(env);
  let d = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    const pj = join(d, "package.json");
    if (existsSync(pj) && existsSync(join(d, "src", "v5", "root", "chain.mjs"))) {
      try { if (JSON.parse(readFileSync(pj, "utf8")).name === "diaporia-safebox") return d; } catch { /* keep looking */ }
    }
    d = dirname(d);
  }
  throw new Error("Cannot locate the diaporia-safebox repository root (set SAFEBOX_REPO_ROOT)");
}

const imp = async <T>(rel: string): Promise<T> => (await import(pathToFileURL(join(safeboxRoot(), rel)).href)) as T;

/** Minimal typed view of the V5 modules this adapter reads. Everything else stays opaque. */
export interface V5Holds {
  merchantHolds(state: unknown, recipientId: string, at: number): unknown[];
  credentialHolds(state: unknown, credId: string, at: number): unknown[];
  effectiveHolds(state: unknown, at: number): Array<{ holdId: string; class: string; scope: { kind: string; target: string } }>;
}
export interface V5Chain { projectState(state: unknown, at: number): any }
export interface V3Capsule {
  purposeViolations(purpose: unknown, p: { operation: string; recipientId: string; asset: string; amountYocto: string; sku: string | null; now: number; capExpiresAt: number; capIssuedAt: number },
    spent: { cumulativeYocto: string; last24hYocto: string }): string[];
}
export interface V3Canon { canon(o: unknown): string }

export interface V5Modules { holds: V5Holds; chain: V5Chain; capsule: V3Capsule; canon: V3Canon }

let cached: Promise<V5Modules> | null = null;
export function loadV5(): Promise<V5Modules> {
  cached ??= (async () => ({
    holds: await imp<V5Holds>("src/v5/root/holds.mjs"),
    chain: await imp<V5Chain>("src/v5/root/chain.mjs"),
    capsule: await imp<V3Capsule>("src/v3/root/capsule.mjs"),
    canon: await imp<V3Canon>("src/v3/common/canon.mjs"),
  }))();
  return cached;
}
