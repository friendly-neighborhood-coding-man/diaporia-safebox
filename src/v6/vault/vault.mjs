// SafeBox V6 Execution Vault = the V5/V5.1 vault UNCHANGED (own Root replica, exact capability, FIXED_600 buffer,
// anomaly delay, HIGH-risk unresolved expiry, holds, limits, 26 h settlement horizon, Rapid-Use, delegation) plus the
// owner-signed V6 payment-approval policy, checked against the vault's OWN replayed V6 Root replica:
//   * PER_TRANSACTION: every owner paycap must carry the V6 binding + the Root-issued one-time challenge (+ the
//     fingerprint gate for fingerprint-only credentials); the challenge nonce is consumed durably (single use).
//   * the order of checks keeps F-V5-04: the owner's WebAuthn signature is authenticated BEFORE any V6 policy check,
//     so an unauthenticated submitter learns only the authentication error.
//   * bounded delegation is a separate policy (BOUNDED_DELEGATION_ALLOWED): delegated ops never need a new fingerprint;
//     DELEGATION_DISABLED refuses them.
import { fail } from '../../v3/common/canon.mjs';
import { verifyPaycap } from '../../v3/vault/paycap.mjs';
import { ExecutionVaultV5 } from '../../v5/vault/vault.mjs';
import { verifyPaymentApproval } from './payment-approval.mjs';

const V6_SCHEMA = `
CREATE TABLE IF NOT EXISTS v6_challenges (nonce TEXT PRIMARY KEY, cap_id TEXT NOT NULL, payment_id TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS v6_evidence (cap_id TEXT PRIMARY KEY, payment_id TEXT NOT NULL, binding TEXT NOT NULL, grant_ TEXT NOT NULL, gate TEXT, level TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS v6_challenges_no_delete BEFORE DELETE ON v6_challenges BEGIN SELECT RAISE(ABORT, 'append-only'); END;
`;

export class ExecutionVaultV6 extends ExecutionVaultV5 {
  constructor(cfg, deps) {
    super(cfg, deps);
    if (this.root.v6?.protocol !== 'safebox.v6') fail('VAULT_REPLICA_NOT_V6');
    this.store.db.exec(V6_SCHEMA);
  }
  policy6() { return this.root.v6.policy; }
  propose(args) {
    const appr = args?.approval;
    let v6, inner = args;
    if (appr && typeof appr === 'object' && !Array.isArray(appr) && 'v6' in appr) { const { v6: x, ...rest } = appr; v6 = x; inner = { ...args, approval: rest }; }
    const needs = this.policy6().payment.mode === 'PER_TRANSACTION' || v6 !== undefined;
    let pre = null;
    if (needs) {
      try {
        // authenticate the owner's signature first (pure check on the replica; super.propose re-verifies and reserves)
        if (this.rootAlarm()) fail('ROOT_INTEGRITY_ALARM');
        const floor = (c) => this.store.db.prepare('SELECT n FROM sign_floor WHERE cred_id=?').get(c)?.n ?? 0;
        const v = verifyPaycap(this.root, { capability: inner?.capability, approval: inner?.approval }, { now: this.now(), signCountFloor: floor });
        pre = verifyPaymentApproval(this.root, { cap: v.cap, credId: v.credId, v6 }, this.now());
        if (this.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(pre.nonce)) fail('CHALLENGE_ALREADY_CONSUMED');
      } catch (e) {
        this.store.decision('gz', 'PROPOSE', 'DENY', [e.code ?? 'INVALID'], args?.capability?.capId ?? null);
        try { this.journal?.writer('VAULT').attempt({ type: 'OWNER_APPROVAL_REJECTED', principal: '-', outcome: String(e.code ?? 'INVALID') }); } catch {}
        throw e;
      }
    }
    // P0.3 (issue #14): the challenge nonce and the approval evidence are written INSIDE the V3 reservation transaction
    // (proposeTxRecord), so a crash or a second Vault worker can never leave a payment without its evidence, or one
    // Root challenge with two payments. The pre-check above is only an early, cheap denial.
    this.#pending = pre ? { pre, v6, capId: inner.capability?.capId } : null;
    let out;
    try { out = super.propose(inner); } finally { this.#pending = null; }
    if (pre) {
      try { this.journal?.writer('VAULT').append({ type: 'OWNER_PAYMENT_APPROVAL_VERIFIED', relatedId: out.paymentId, outcome: pre.level,
        data: { requestId: pre.binding.requestId, policyVersion: pre.binding.policyVersion, assurance: pre.binding.assurance } }); } catch (e) { if (e.code === 'JOURNAL_PRIVACY_VIOLATION') throw e; }
    }
    return out;
  }
  #pending = null;
  proposeTxRecord(ctx) {
    super.proposeTxRecord(ctx);
    const p = this.#pending;
    if (!p) {
      // an owner paycap reaching the V3 core without the V6 pre-verification is impossible by construction under
      // PER_TRANSACTION; fail closed instead of committing a payment with no approval evidence
      if (this.policy6().payment.mode === 'PER_TRANSACTION') fail('V6_PAYMENT_APPROVAL_REQUIRED', 'no verified approval in this transaction');
      return;
    }
    if (p.capId !== ctx.cap.capId) fail('V6_APPROVAL_CONTEXT_MISMATCH');
    // durable single use, decided inside the same IMMEDIATE transaction as the payment rows (serialises workers)
    if (this.store.db.prepare('SELECT 1 FROM v6_challenges WHERE nonce=?').get(p.pre.nonce)) fail('CHALLENGE_ALREADY_CONSUMED', 'in transaction');
    this.store.db.prepare('INSERT INTO v6_challenges (nonce, cap_id, payment_id, at) VALUES (?,?,?,?)').run(p.pre.nonce, ctx.cap.capId, ctx.paymentId, this.now());
    this.store.db.prepare('INSERT INTO v6_evidence (cap_id, payment_id, binding, grant_, gate, level) VALUES (?,?,?,?,?,?)')
      .run(ctx.cap.capId, ctx.paymentId, JSON.stringify(p.pre.binding), JSON.stringify(p.v6.grant), p.v6.gate ? JSON.stringify(p.v6.gate) : null, p.pre.level);
  }
  proposeDelegated(req) {
    if (this.policy6().delegation !== 'BOUNDED_DELEGATION_ALLOWED') fail('DELEGATION_DISABLED_BY_POLICY');
    return super.proposeDelegated(req);
  }
  v6evidence() { return this.store.db.prepare('SELECT * FROM v6_evidence ORDER BY payment_id').all(); }
}
