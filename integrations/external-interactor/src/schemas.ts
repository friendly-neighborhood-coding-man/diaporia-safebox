import { z } from "zod";

/** MOCK mode: only reserved `.mock` ledger accounts (same rule as the V2 Mock Ledger). */
export const recipientId = z.string().max(45).regex(/^[a-z0-9][a-z0-9-]{1,40}\.mock$/, "recipientId must be a MOCK ledger account such as merchant-a.mock");
/** Integer yoctoNEAR as a decimal string, no sign, no leading zeros, no exponent, at most 39 digits. */
export const yocto = z.string().max(39).regex(/^[1-9][0-9]{0,38}$/, "amountYocto must be a positive integer yoctoNEAR decimal string");
export const asset = z.literal("NEAR");
export const requestId = z.string().regex(/^apr_[0-9a-f]{32}$/, "requestId must be an apr_… id");
export const idempotencyKey = z.string().regex(/^[A-Za-z0-9_-]{16,64}$/, "idempotencyKey: 16-64 characters of A-Z a-z 0-9 _ -");
/** Untrusted free text; printable ASCII only is kept (sanitized again server-side). */
export const memo = z.string().max(140);

export const INPUTS = {
  get_safebox_status: z.strictObject({}),
  check_payment: z.strictObject({ recipientId, amountYocto: yocto, asset }),
  prepare_payment: z.strictObject({ recipientId, amountYocto: yocto, asset, memo: memo.optional(), idempotencyKey }),
  get_payment_status: z.strictObject({ requestId }),
};

const paymentOut = z.object({ recipientId: z.string(), amountYocto: z.string(), asset: z.literal("NEAR") });
export const OUTPUTS = {
  get_safebox_status: z.object({
    accountRef: z.string(), environment: z.literal("MOCK"), observedAt: z.string(),
    protection: z.object({ frozen: z.boolean(), emergencyLockdown: z.boolean(), activeHolds: z.number().int(), activeHoldsByScope: z.record(z.string(), z.number()), rapidUseActive: z.boolean(), blockers: z.array(z.string()) }),
    purpose: z.object({ purposeId: z.string(), version: z.string(), asset: z.string(), allowedRecipients: z.array(z.string()), perPaymentMaxYocto: z.string(), dailyLimitYocto: z.string(), remainingDailyYocto: z.string() }),
    epoch: z.string(), settlement: z.object({ minimumBufferMs: z.number(), configuredBufferMs: z.number(), note: z.string() }),
    pendingApprovalRequests: z.number().int(), redaction: z.string(),
  }),
  check_payment: z.object({
    isAuthorization: z.literal(false), environment: z.literal("MOCK"), observedAt: z.string(), wouldBeAcceptedForOwnerApproval: z.boolean(),
    policyViolations: z.array(z.string()), blockers: z.array(z.string()), payment: paymentOut,
    estimate: z.object({ feeYocto: z.string(), feeModel: z.literal("MOCK_LEDGER_NO_FEE"), minimumBufferMs: z.number(), configuredBufferMs: z.number(), anomalyDelay: z.string() }),
    statement: z.string(),
  }),
  prepare_payment: z.object({
    requestId: z.string(), state: z.string(), requestDigest: z.string(), expiresAt: z.string(), payment: paymentOut,
    boundTo: z.object({ purposeId: z.string(), purposeVersion: z.string(), epoch: z.string() }),
    ownerAction: z.object({ kind: z.literal("APPROVE_ON_ENROLLED_SAFEBOX_DEVICE"), deviceIntent: z.string(), instruction: z.string() }),
    paymentEffect: z.literal("NONE"), signed: z.literal(false), settled: z.literal(false), idempotentReplay: z.boolean(),
  }),
  get_payment_status: z.object({
    requestId: z.string(), requestState: z.string(), environment: z.literal("MOCK"), observedAt: z.string(), expiresAt: z.string(), payment: paymentOut,
    vault: z.object({ paymentId: z.string(), vaultState: z.string(), releaseAt: z.string().nullable(), reason: z.string().nullable() }).nullable(),
    ledgerReceipt: z.object({ txId: z.string(), ledgerStatus: z.string(), matchesRequest: z.boolean() }).nullable(),
    vaultRejectionCode: z.string().nullable(), settledVerified: z.boolean(), stateIsVerifiedBy: z.literal("SAFEBOX_VAULT_AND_MOCK_LEDGER"), statement: z.string(),
  }),
};

/** Structural bound applied to every JSON-RPC body before the MCP transport sees it. */
export function jsonDepth(v: unknown, d = 0): number {
  if (d > 64) return d;
  if (Array.isArray(v)) return v.reduce((m: number, x) => Math.max(m, jsonDepth(x, d + 1)), d + 1);
  if (v && typeof v === "object") return Object.values(v).reduce((m: number, x) => Math.max(m, jsonDepth(x, d + 1)), d + 1);
  return d;
}
