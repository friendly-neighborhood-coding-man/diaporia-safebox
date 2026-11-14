export const SCOPES = {
  STATUS: "safebox.status.read",
  CHECK: "safebox.payment.check",
  PREPARE: "safebox.payment.prepare",
  PAYMENT_READ: "safebox.payment.read",
} as const;
export type Scope = (typeof SCOPES)[keyof typeof SCOPES];
export const ALL_SCOPES: Scope[] = [SCOPES.STATUS, SCOPES.CHECK, SCOPES.PREPARE, SCOPES.PAYMENT_READ];
/** Granted when a client asks for none: never the preparation scope. */
export const DEFAULT_SCOPES: Scope[] = [SCOPES.STATUS, SCOPES.PAYMENT_READ];

/** A verified AI-client principal. The SafeBox account comes from here, never from tool arguments. */
export interface Principal {
  userId: string;
  accountRef: string;
  clientId: string;
  scopes: ReadonlySet<string>;
  kind: "OAUTH_ACCESS_TOKEN";
  tokenFingerprint: string;
}
