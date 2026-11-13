// Sensitive Zone execution service (V2).
// Authorization (owner-signed policy + owner-signed single-use task capability), execution
// (mock executor key, used ONLY at release) and verification (ledger status) are separate steps.
// Nothing the caller says about its own permissions is trusted: every decision is derived from
// owner-signed statements verified against keys pinned in trusted configuration.
import { randomBytes, randomUUID } from 'node:crypto';
import { fail, SafeBoxError, atomicAmount, requireExactFields } from '../../v1/canonical.mjs';
import { V2_DOMAINS } from '../common/crypto.mjs';
import { openPolicy, openCapability, openRevocation, openUnfreeze, mockAccount } from './statements.mjs';
import { evaluatePayment, evaluateRelease } from './policy.mjs';
import { SensitiveStore } from './store.mjs';
import { LEDGER_TX_VERSION } from '../mock-ledger/ledger.mjs';

const MEMO_RE = /^[\x20-\x7e]{0,280}$/;
const LEDGER_DEFINITIVE = /^LEDGER_(BAD_TX|BAD_SIGNATURE|UNSUPPORTED_ASSET|WRONG_SENDER|AMOUNT_OVER_CAP|UNKNOWN_RECIPIENT|SELF_TRANSFER|INSUFFICIENT_FUNDS)$/;

export class SensitiveZone {
  /**
   * @param cfg trusted configuration (written by the launcher, not by any zone):
   *   trustedOwnerKeys {principalId: keyId}, operatorKey, executorAccount, minBufferMs, leaseMs, injectFlaw
   * @param deps { store, now (virtual ms), wallNow (real ms), executorSigner, ledger (client with call()) }
   */
  constructor(cfg, { store, now, wallNow = () => Date.now(), executorSigner, ledger }) {
    this.cfg = Object.freeze({ minBufferMs: 600_000, leaseMs: 5_000, injectFlaw: null, ...cfg,
      trustedOwnerKeys: Object.freeze({ ...cfg.trustedOwnerKeys }) });
    this.store = store; this.now = now; this.wallNow = wallNow;
    this.executor = executorSigner; this.ledger = ledger;
    this.leaseUntil = 0; // in memory only: after a restart releases stay blocked until the watchdog checks in
    this.busy = false;
  }

  #activePolicy(principalId) {
    const row = this.store.db.prepare('SELECT * FROM policies WHERE principal_id=? ORDER BY loaded_at DESC, rowid DESC LIMIT 1').get(principalId);
    if (!row) return null;
    // Re-verify from the stored signed bytes on every use (stored state is not trusted blindly).
    const { policy, digest } = openPolicy({ statement: row.statement, signature: row.signature }, this.cfg.trustedOwnerKeys, this.cfg);
    if (digest !== row.digest) fail('STORED_POLICY_CORRUPT');
    return { policy, digest };
  }
  #capRevoked(capId) { return !!this.store.db.prepare('SELECT 1 FROM caps_revoked WHERE cap_id=?').get(capId); }
  #capUsed(capId) { return !!this.store.db.prepare('SELECT 1 FROM caps_used WHERE cap_id=?').get(capId); }

  // ---------------- General Zone facing (untrusted caller) ----------------
  propose(args) {
    const codes = [];
    let cap = null;
    try {
      requireExactFields(args, ['capability', 'recipientId', 'amountYocto', 'asset', 'memo']);
      mockAccount(args.recipientId, 'recipientId');
      atomicAmount(args.amountYocto, 'amountYocto');
      if (typeof args.asset !== 'string' || args.asset.length > 16) fail('INVALID_ASSET');
      if (typeof args.memo !== 'string' || !MEMO_RE.test(args.memo)) fail('INVALID_MEMO');
      cap = openCapability(args.capability, this.cfg.trustedOwnerKeys);
    } catch (e) { this.store.decision('gz', 'PROPOSE', 'DENY', [e.code ?? 'INVALID'], cap?.capId ?? null); throw e; }

    const paymentId = 'p_' + randomUUID().replaceAll('-', '');
    const now = this.now();
    let out;
    try {
      out = this.store.tx(() => {
        const control = this.store.control();
        const pol = this.#activePolicy(cap.principalId);
        const facts = { policy: pol?.policy ?? null, cap, req: { recipientId: args.recipientId, asset: args.asset, amountYocto: args.amountYocto },
          now, usage: this.store.usage(cap.principalId), capUsed: this.#capUsed(cap.capId), capRevoked: this.#capRevoked(cap.capId),
          control, flaw: this.cfg.injectFlaw };
        const d = evaluatePayment(facts);
        if (d.decision !== 'ALLOW') return { denied: d.deny };
        const bufferMs = Number(pol.policy.bufferMs);
        this.store.db.prepare(`INSERT INTO payments (payment_id, cap_id, cap_digest, principal_id, policy_id, policy_digest, recipient, asset, amount,
          intent_nonce, state, proposed_at, cap_expires_at, memo, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?, 'PROPOSED', ?,?,?,?)`)
          .run(paymentId, cap.capId, cap.digest, cap.principalId, pol.policy.policyId, pol.digest, args.recipientId, args.asset, args.amountYocto,
            randomBytes(16).toString('hex'), now, Date.parse(cap.expiresAt), args.memo, now);
        this.store.journal(paymentId, null, 'PROPOSED', 'general-zone', { capId: cap.capId, taskRef: cap.taskRef, recipient: args.recipientId, amount: args.amountYocto });
        this.store.db.prepare('INSERT INTO caps_used (cap_id, payment_id) VALUES (?,?)').run(cap.capId, paymentId);
        this.store.move(paymentId, 'PROPOSED', 'AUTHORIZED', 'policy', { decision: 'ALLOW', policyDigest: pol.digest, capDigest: cap.digest });
        this.store.move(paymentId, 'AUTHORIZED', 'RESERVED', 'policy', { reservedYocto: args.amountYocto });
        const row = this.store.move(paymentId, 'RESERVED', 'BUFFERED', 'policy', { releaseAt: now + bufferMs, bufferMs }, { release_at: now + bufferMs });
        return { row };
      });
    } catch (e) { this.store.decision('gz', 'PROPOSE', 'ERROR', [e.code ?? 'INTERNAL'], cap.capId); throw e; }
    if (out.denied) { this.store.decision('gz', 'PROPOSE', 'DENY', out.denied, cap.capId); fail('POLICY_DENY', out.denied.join(',')); }
    this.store.decision('gz', 'PROPOSE', 'ALLOW', [], cap.capId, paymentId);
    return { paymentId, state: out.row.state, releaseAt: out.row.release_at };
  }

  status(paymentId) {
    if (typeof paymentId !== 'string' || !/^p_[0-9a-f]{32}$/.test(paymentId)) fail('INVALID_ID');
    const r = this.store.get(paymentId);
    if (!r) fail('UNKNOWN_PAYMENT');
    return { paymentId, state: r.state, recipient: r.recipient, amountYocto: r.amount, releaseAt: r.release_at, txId: r.tx_id, reason: r.reason };
  }

  // ---------------- Supervisor facing (control channel) ----------------
  loadPolicy(signed) {
    const { policy, digest } = openPolicy(signed, this.cfg.trustedOwnerKeys, this.cfg);
    this.store.tx(() => {
      if (this.store.db.prepare('SELECT 1 FROM policies WHERE policy_id=?').get(policy.policyId)) fail('POLICY_EXISTS');
      this.store.db.prepare('INSERT INTO policies (policy_id, principal_id, statement, signature, digest, loaded_at) VALUES (?,?,?,?,?,?)')
        .run(policy.policyId, policy.principalId, signed.statement, signed.signature, digest, this.now());
      this.store.journal(null, null, null, 'supervisor', { event: 'POLICY_LOADED', policyId: policy.policyId, digest });
    });
    return { policyId: policy.policyId, digest };
  }

  revokeCapability(signed) {
    const r = openRevocation(signed, this.cfg.trustedOwnerKeys);
    return this.store.tx(() => {
      this.store.db.prepare('INSERT OR IGNORE INTO caps_revoked (cap_id, at, statement) VALUES (?,?,?)').run(r.capId, this.now(), signed.statement);
      this.store.journal(null, null, null, 'owner', { event: 'CAPABILITY_REVOKED', capId: r.capId });
      const used = this.store.db.prepare('SELECT payment_id FROM caps_used WHERE cap_id=?').get(r.capId);
      let cancelled = null;
      if (used && this.store.get(used.payment_id)?.state === 'BUFFERED') {
        this.store.move(used.payment_id, 'BUFFERED', 'CANCELLED', 'owner', { reason: 'capability revoked during buffer' }, { reason: 'CAPABILITY_REVOKED' });
        cancelled = used.payment_id;
      }
      return { capId: r.capId, cancelled };
    });
  }

  heartbeat() { this.leaseUntil = this.wallNow() + this.cfg.leaseMs; return { leaseUntil: this.leaseUntil }; }

  setLevel(level, reason, classification, actor = 'supervisor') {
    if (!['HOLD', 'FROZEN'].includes(level)) fail('BAD_LEVEL');
    return this.store.tx(() => {
      const cur = this.store.control();
      if (cur.level === 'FROZEN' && level === 'HOLD') return { level: 'FROZEN', frozenNow: [] }; // never downgrade a freeze
      if (cur.level !== level) {
        this.store.setControl('level', level); this.store.setControl('reason', String(reason).slice(0, 200));
        this.store.setControl('since', String(this.now())); this.store.setControl('classification', String(classification).slice(0, 40));
        this.store.journal(null, null, null, actor, { event: level === 'FROZEN' ? 'FREEZE' : 'HOLD', reason, classification });
      }
      const frozenNow = [];
      if (level === 'FROZEN') for (const r of this.store.byState(['BUFFERED'])) { this.store.move(r.payment_id, 'BUFFERED', 'FROZEN', actor, { reason: 'emergency freeze' }, { reason: 'FROZEN' }); frozenNow.push(r.payment_id); }
      return { level, frozenNow };
    });
  }

  clearHold(reviewRef) {
    return this.store.tx(() => {
      const cur = this.store.control();
      if (cur.level !== 'HOLD') fail('NOT_ON_HOLD');
      this.store.setControl('level', 'NONE'); this.store.journal(null, null, null, 'supervisor', { event: 'HOLD_CLEARED', reviewRef: String(reviewRef).slice(0, 64) });
      return { level: 'NONE' };
    });
  }

  /** Lifting a freeze needs an operator(owner)-signed statement bound to this exact freeze. Frozen payments are cancelled, never auto-released. */
  async unfreeze(signed) {
    const u = openUnfreeze(signed, this.cfg.operatorKey);
    const cur = this.store.control();
    if (cur.level !== 'FROZEN') fail('NOT_FROZEN');
    if (u.target !== 'sensitive-zone' || u.frozenAt !== cur.since) fail('UNFREEZE_NOT_BOUND_TO_THIS_FREEZE');
    // Before cancelling, ask the ledger about every frozen payment that was already signed: truth on the ledger wins.
    for (const r of this.store.byState(['FROZEN'])) if (r.tx_statement) await this.#reconcileOne(r, { fromFrozen: true });
    return this.store.tx(() => {
      const cancelled = [];
      for (const r of this.store.byState(['FROZEN'])) { this.store.move(r.payment_id, 'FROZEN', 'CANCELLED', 'operator', { reason: 'cancelled on unfreeze' }, { reason: 'CANCELLED_AFTER_FREEZE' }); cancelled.push(r.payment_id); }
      this.store.setControl('level', 'NONE'); this.store.journal(null, null, null, 'operator', { event: 'UNFREEZE', reviewRef: u.reviewRef });
      return { level: 'NONE', cancelled };
    });
  }

  /** Processes due releases and reconciles in-flight transfers. Driven by the supervisor's clock tick. */
  async tick() {
    if (this.busy) return { skipped: 'busy' };
    this.busy = true;
    try {
      const out = { released: [], settled: [], blocked: [], expired: [], failed: [], unknown: [] };
      await this.reconcile(out);
      const now = this.now();
      for (const row of this.store.byState(['BUFFERED'])) {
        if (row.release_at > now) continue;
        const res = this.#releaseOne(row.payment_id);
        if (res.blocked) { out.blocked.push({ paymentId: row.payment_id, deny: res.blocked }); continue; }
        if (res.expired) { out.expired.push(row.payment_id); continue; }
        out.released.push(row.payment_id);
        await this.#submit(res.row, out);
      }
      return out;
    } finally { this.busy = false; }
  }

  #releaseOne(paymentId) {
    return this.store.tx(() => {
      const row = this.store.get(paymentId);
      if (row.state !== 'BUFFERED') return { blocked: ['STATE_CHANGED'] };
      const now = this.now();
      let pol = null;
      try { pol = this.#activePolicy(row.principal_id); } catch { pol = null; }
      const d = evaluateRelease({ control: this.store.control(), leaseFresh: this.wallNow() <= this.leaseUntil, policy: pol?.policy ?? null,
        policyDigest: pol?.digest ?? null, row, now, capRevoked: this.#capRevoked(row.cap_id), executions: this.store.usage(row.principal_id).executions });
      if (d.decision !== 'ALLOW') {
        if (d.deny.length === 1 && d.deny[0] === 'CAPABILITY_EXPIRED') {
          this.store.move(paymentId, 'BUFFERED', 'EXPIRED', 'policy', { deny: d.deny }, { reason: 'CAPABILITY_EXPIRED' });
          return { expired: true };
        }
        return { blocked: d.deny };
      }
      const keyNonce = (BigInt(this.store.getControl('lastKeyNonce')) + 1n).toString();
      this.store.setControl('lastKeyNonce', keyNonce);
      const signed = this.executor.sign(V2_DOMAINS.LEDGER_TX, { v: LEDGER_TX_VERSION, paymentId: row.payment_id, capId: row.cap_id, intentNonce: row.intent_nonce,
        keyNonce, sender: this.cfg.executorAccount, recipient: row.recipient, asset: row.asset, amountYocto: row.amount, issuedAt: new Date(now).toISOString() });
      // Signed bytes are made durable BEFORE they leave the zone: recovery re-submits these exact bytes, never a new transfer.
      const r2 = this.store.move(paymentId, 'BUFFERED', 'RELEASED', 'executor', { keyNonce, finalCheck: 'ALLOW' },
        { key_nonce: keyNonce, tx_statement: signed.statement, tx_signature: signed.signature, released_at: now });
      return { row: r2 };
    });
  }

  async #submit(row, out, resigned = false) {
    let res;
    try { res = await this.ledger.call('SUBMIT_TX', { tx: { statement: row.tx_statement, signature: row.tx_signature } }); }
    catch (e) {
      const code = e instanceof SafeBoxError ? e.code : 'LEDGER_TRANSPORT';
      if (code === 'LEDGER_KEY_NONCE_STALE' && !resigned) {
        // The ledger checked tx-id idempotency first, so a stale key nonce PROVES these bytes were never accepted
        // and never can be. Re-sign the same payment (same paymentId + one-use intent nonce => still at most one effect).
        const r2 = this.#resign(row.payment_id);
        if (r2) return this.#submit(r2, out, true);
      }
      this.store.tx(() => {
        const cur = this.store.get(row.payment_id);
        if (code === 'LEDGER_FROZEN') this.store.move(row.payment_id, cur.state, 'FROZEN', 'executor', { ledger: code }, { reason: 'LEDGER_FROZEN' });
        else if (LEDGER_DEFINITIVE.test(code)) this.store.move(row.payment_id, cur.state, 'FAILED', 'executor', { ledger: code }, { reason: code });
        else if (cur.state !== 'UNKNOWN') this.store.move(row.payment_id, cur.state, 'UNKNOWN', 'executor', { ledger: code }, { reason: code });
      });
      (code === 'LEDGER_FROZEN' ? out.blocked : LEDGER_DEFINITIVE.test(code) ? out.failed : out.unknown).push(row.payment_id);
      return;
    }
    this.#applyLedgerStatus(row.payment_id, res, out);
  }

  #resign(paymentId) {
    return this.store.tx(() => {
      const row = this.store.get(paymentId);
      if (!['RELEASED', 'UNKNOWN'].includes(row.state)) return null;
      if (this.store.control().level !== 'NONE' || !(this.wallNow() <= this.leaseUntil)) return null; // a re-sign is a release: same gates
      const keyNonce = (BigInt(this.store.getControl('lastKeyNonce')) + 1n).toString();
      this.store.setControl('lastKeyNonce', keyNonce);
      const signed = this.executor.sign(V2_DOMAINS.LEDGER_TX, { v: LEDGER_TX_VERSION, paymentId: row.payment_id, capId: row.cap_id, intentNonce: row.intent_nonce,
        keyNonce, sender: this.cfg.executorAccount, recipient: row.recipient, asset: row.asset, amountYocto: row.amount, issuedAt: new Date(this.now()).toISOString() });
      this.store.journal(paymentId, null, null, 'executor', { event: 'RESIGN_AFTER_PROOF_NOT_INCLUDED', supersededKeyNonce: row.key_nonce, keyNonce });
      this.store.db.prepare('UPDATE payments SET key_nonce=?, tx_statement=?, tx_signature=?, tx_id=NULL, updated_at=? WHERE payment_id=?')
        .run(keyNonce, signed.statement, signed.signature, this.now(), paymentId);
      return this.store.get(paymentId);
    });
  }

  #applyLedgerStatus(paymentId, st, out) {
    this.store.tx(() => {
      const cur = this.store.get(paymentId);
      if (st.status === 'VOIDED') {
        // Voided by the ledger while frozen (never credited): the payment failed; its reservation is released.
        this.store.move(paymentId, cur.state, cur.state === 'FROZEN' ? 'CANCELLED' : 'FAILED', 'verifier', { txId: st.txId, ledger: 'VOIDED' }, { tx_id: st.txId, ledger_status: 'VOIDED', reason: 'LEDGER_VOIDED' });
      } else if (st.status === 'SETTLED') {
        this.store.move(paymentId, cur.state, 'SETTLED', 'verifier', { txId: st.txId }, { tx_id: st.txId, ledger_status: 'SETTLED', settled_at: this.now() });
        out?.settled.push(paymentId);
      } else if (cur.tx_id !== st.txId || cur.ledger_status !== st.status) {
        this.store.db.prepare('UPDATE payments SET tx_id=?, ledger_status=?, updated_at=? WHERE payment_id=?').run(st.txId, st.status, this.now(), paymentId);
        this.store.journal(paymentId, null, null, 'verifier', { ledgerStatus: st.status, txId: st.txId });
      }
    });
  }

  async #reconcileOne(row, { fromFrozen = false } = {}) {
    if (!fromFrozen) {
      // Re-submit the identical signed bytes: the ledger is idempotent on tx id and one-use intent nonce.
      return this.#submit(row, { settled: [], blocked: [], failed: [], unknown: [] });
    }
    let st;
    try { st = await this.ledger.call('TX_STATUS', { txId: txIdOf(row) }); } catch { fail('LEDGER_UNAVAILABLE_FOR_RECONCILE'); }
    if (st.found && st.status === 'SETTLED') this.#applyLedgerStatus(row.payment_id, st, null);
    else if (st.found) fail('FROZEN_PAYMENT_PENDING_ON_LEDGER'); // ledger holds it pending: cannot cancel safely
  }

  /** Crash recovery / in-flight reconciliation. Never signs a new transfer for an already-released payment. */
  async reconcile(out = { released: [], settled: [], blocked: [], failed: [], unknown: [] }) {
    for (const row of this.store.byState(['RELEASED', 'UNKNOWN'])) {
      if (this.store.control().level === 'FROZEN') {
        // Frozen: do not push anything new to the ledger; only learn whether it already happened.
        let st; try { st = await this.ledger.call('TX_STATUS', { txId: txIdOf(row) }); } catch { continue; }
        if (st.found) this.#applyLedgerStatus(row.payment_id, st, out);
        else this.store.tx(() => this.store.move(row.payment_id, row.state, 'FROZEN', 'executor', { reason: 'frozen before ledger acceptance' }, { reason: 'FROZEN' }));
        continue;
      }
      if (row.tx_id && row.ledger_status === 'PENDING') {
        let st; try { st = await this.ledger.call('TX_STATUS', { txId: row.tx_id }); } catch { continue; }
        if (st.found) { this.#applyLedgerStatus(row.payment_id, st, out); continue; }
      }
      await this.#submit(row, out);
    }
    return out;
  }

  state() {
    const counts = Object.fromEntries(this.store.db.prepare('SELECT state, COUNT(*) n FROM payments GROUP BY state').all().map(r => [r.state, r.n]));
    return { control: this.store.control(), counts, leaseFresh: this.wallNow() <= this.leaseUntil, injectFlaw: this.cfg.injectFlaw,
      journal: this.store.verifyJournal(), executorPublicKey: this.executor.publicKey };
  }
  payments() { return this.store.db.prepare('SELECT payment_id, cap_id, principal_id, recipient, amount, state, proposed_at, release_at, released_at, settled_at, tx_id, reason FROM payments ORDER BY proposed_at, payment_id').all(); }
}

import { digestOf } from '../common/crypto.mjs';
const txIdOf = (row) => row.tx_id ?? digestOf(V2_DOMAINS.LEDGER_TX, row.tx_statement);

/** IPC op tables. gz = General Zone (untrusted), ctl = Supervisor only. */
export function sensitiveOps(zone) {
  const gz = {
    PROPOSE: { fields: ['capability', 'recipientId', 'amountYocto', 'asset', 'memo'], types: { capability: 'signed' }, maxLen: { memo: 512 },
      handler: (a) => zone.propose(a) },
    STATUS: { fields: ['paymentId'], handler: (a) => zone.status(a.paymentId) },
    HEALTH: { fields: [], handler: () => ({ ok: true, level: zone.store.control().level }) },
  };
  const ctl = {
    LOAD_POLICY: { fields: ['policy'], types: { policy: 'signed' }, handler: (a) => zone.loadPolicy(a.policy) },
    REVOKE_CAP: { fields: ['revocation'], types: { revocation: 'signed' }, handler: (a) => zone.revokeCapability(a.revocation) },
    HEARTBEAT: { fields: [], handler: () => zone.heartbeat() },
    HOLD: { fields: ['reason', 'classification'], handler: (a) => zone.setLevel('HOLD', a.reason, a.classification) },
    FREEZE: { fields: ['reason', 'classification'], handler: (a) => zone.setLevel('FROZEN', a.reason, a.classification) },
    CLEAR_HOLD: { fields: ['reviewRef'], handler: (a) => zone.clearHold(a.reviewRef) },
    UNFREEZE: { fields: ['unfreeze'], types: { unfreeze: 'signed' }, handler: (a) => zone.unfreeze(a.unfreeze) },
    TICK: { fields: [], handler: () => zone.tick() },
    STATE: { fields: [], handler: () => zone.state() },
    PAYMENTS: { fields: [], handler: () => zone.payments() },
    JOURNAL: { fields: ['sinceSeq'], handler: (a) => zone.store.journalRows(Number(a.sinceSeq) || 0) },
    DECISIONS: { fields: [], handler: () => zone.store.db.prepare('SELECT * FROM decisions ORDER BY seq').all() },
  };
  return { gz, ctl };
}

export { SensitiveStore };
