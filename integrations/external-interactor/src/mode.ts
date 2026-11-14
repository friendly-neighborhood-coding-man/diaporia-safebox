import { SCOPES } from "./auth/scopes.js";

/**
 * Deployment modes. There are exactly two and no flag widens either:
 *  - mock-loopback: loopback-bound host AND loopback base URL; MOCK ledger only; all four tools (prepare needs its scope).
 *  - public-readonly: https base URL; status/check/payment-status only; prepare_payment is never registered and its
 *    scope is never offered. Payment preparation on a public endpoint needs a separate security review and new code.
 */
export type DeploymentMode = "mock-loopback" | "public-readonly";
const LOOPBACK = /^(127\.0\.0\.1|localhost|\[::1\]|::1)$/;
export const isLoopbackHost = (h: string) => LOOPBACK.test(h);
export function isLoopbackUrl(u: string): boolean { try { return LOOPBACK.test(new URL(u).hostname); } catch { return false; } }

export interface ModePolicy { mode: DeploymentMode; offeredScopes: string[]; preparationEnabled: boolean }

export function resolveMode(mode: string, host: string, baseUrl: string): ModePolicy {
  if (mode === "mock-loopback") {
    if (!isLoopbackHost(host) || !isLoopbackUrl(baseUrl)) throw new Error("mock-loopback mode must bind a loopback host and use a loopback base URL");
    return { mode, offeredScopes: [SCOPES.STATUS, SCOPES.CHECK, SCOPES.PREPARE, SCOPES.PAYMENT_READ], preparationEnabled: true };
  }
  if (mode === "public-readonly") {
    let u: URL; try { u = new URL(baseUrl); } catch { throw new Error("public-readonly mode needs an absolute https base URL"); }
    if (u.protocol !== "https:") throw new Error("public-readonly mode needs an https base URL");
    return { mode, offeredScopes: [SCOPES.STATUS, SCOPES.CHECK, SCOPES.PAYMENT_READ], preparationEnabled: false };
  }
  throw new Error(`Unknown deployment mode: ${mode}`);
}
