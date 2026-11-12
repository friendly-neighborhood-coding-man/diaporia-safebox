// SafeBox V1 service: proposal -> sealed intent -> owner authorization -> atomic reservation
// -> executor sign -> durable record -> broadcast -> independent verification / reconciliation.
import { randomBytes } from 'node:crypto';
import { fail, SafeBoxError } from './canonical.mjs';
import { buildIntent, parseSealedIntent, displayIntent, ACTIONS } from './intent.mjs';
import { verifyAuthorization, verifyRevocation, verifyMandate, parseMandate } from './authz.mjs';
import { parseProposal } from './proposal.mjs';
import { SafeBoxStore } from './store.mjs';
import { contractArgsBytes } from './near/executor.mjs';
import { verifyTxOutcome } from './near/verifier.mjs';

// Errors raised before anything is signed that are deterministic (re-trying cannot help).
const DETERMINISTIC_PRESIGN = /^(PRESIGN_|POSTSIGN_|WRONG_|RPC_CHAIN_ID|EXECUTOR_KEY_NOT|SIGNER_NOT|CONTRACT_NOT|INTENT_EXPIRED|STORED_INTENT|AUTHZ_|UNKNOWN_PRINCIPAL|NOT_AUTHORIZED)/;
const NOT_INCLUDED_GRACE_MS = 60 * 60_000; // native mode: trust "not found" only for recently signed txs

export class SafeBoxService {
  constructor({ store, trustedOwnerKeys, signerAccountId, contractId = null, executor = null, rpc = null, now = () => Date.now() }) {
    this.store = store; this.now = now; this.executor = executor; this.rpc = rpc ?? executor?.rpc ?? null;
    this.trustedOwnerKeys = Object.freeze({ ...trustedOwnerKeys });
    this.signerAccountId = signerAccountId; this.contractId = contractId;
  }
  #iso() { return new Date(this.now()).toISOString(); }
  #ownerKey(principalId) { const k = this.trustedOwnerKeys[principalId]; if (!k) fail('UNKNOWN_PRINCIPAL'); return k; }

  // ---- mandates (owner-signed) ----
  registerMandate({ mandate, signature }) {
    const m = parseMandate(mandate);
    verifyMandate({ mandate, signature, trustedOwnerKey: this.#ownerKey(m.principalId) });
    this.store.putMandate({ mandateId: m.mandateId, principalId: m.principalId, statement: mandate, signature });
    return m;
  }
  #checkMandate(row, intent, now) {
    if (!row) fail('UNKNOWN_MANDATE');
    if (row.revoked) fail('MANDATE_REVOKED');
    const m = verifyMandate({ mandate: row.statement, signature: row.signature, trustedOwnerKey: this.#ownerKey(row.principal_id) });
    if (m.principalId !== intent.principalId || row.principal_id !== intent.principalId) fail('CROSS_PRINCIPAL_MANDATE');
    if (m.action !== intent.action) fail('MANDATE_ACTION_MISMATCH');
    if (now < Date.parse(m.validFrom) || now >= Date.parse(m.expiresAt)) fail('MANDATE_NOT_ACTIVE');
    if (!m.allowedRecipients.includes(intent.recipientId)) fail('RECIPIENT_NOT_IN_MANDATE');
    if (BigInt(intent.amountYocto) > BigInt(m.maxPerIntentYocto)) fail('AMOUNT_OVER_MANDATE');
    return m;
  }

  // ---- 1. proposal (untrusted caller) ----
  propose(input) {
    const p = parseProposal(input);
    this.#ownerKey(p.principalId);
    if (p.action === ACTIONS.CONTRACT && !this.contractId) fail('CONTRACT_MODE_NOT_CONFIGURED');
    const now = this.now();
    const sealed = buildIntent({ principalId: p.principalId, mandateId: p.mandateId, action: p.action,
      signerAccountId: this.signerAccountId, contractId: this.contractId, recipientId: p.recipientId,
      amountYocto: p.amountYocto, ttlMs: Number(p.ttlSeconds) * 1000, now });
    const mrow = this.store.getMandate(p.mandateId);
    const m = this.#checkMandate(mrow, sealed.intent, now);
    if (BigInt(mrow.reserved_total) + BigInt(p.amountYocto) > BigInt(m.maxTotalYocto)) fail('MANDATE_TOTAL_EXCEEDED');
    const challenge = randomBytes(32).toString('hex');
    this.store.insertIntent({ sealed, challenge, proposalMeta: JSON.stringify(p.context) });
    return { intentId: sealed.intent.intentId, digest: sealed.digest, canonical: sealed.canonical, challenge, display: displayIntent(sealed) };
  }

  /** What the owner authorizer fetches. The authorizer recomputes the digest itself. */
  authorizationRequest(intentId) {
    const row = this.store.get(intentId);
    if (!row) fail('UNKNOWN_INTENT');
    return { intentId, canonical: row.canonical, challenge: row.challenge, state: row.state };
  }

  // ---- 2. owner authorization ----
  authorize(intentId, { authorization, signature }) {
    if (typeof authorization !== 'string' || authorization.length > 2048) fail('INVALID_AUTHORIZATION');
    const row = this.store.get(intentId);
    if (!row) fail('UNKNOWN_INTENT');
    const sealed = parseSealedIntent(row.canonical);
    const now = this.now();
    if (now >= Date.parse(sealed.intent.expiresAt)) {
      if (['PREPARED', 'AUTHORIZED'].includes(row.state)) this.store.transition(intentId, row.state, 'EXPIRED', { detail: { reason: 'intent expired' } });
      fail('INTENT_EXPIRED');
    }
    return this.store.transition(intentId, 'PREPARED', 'AUTHORIZED', {
      actor: 'owner',
      patch: { authz: authorization, authz_sig: signature },
      detail: { ownerKey: this.trustedOwnerKeys[sealed.intent.principalId] ?? null },
      guard: (r) => verifyAuthorization({ sealed, authorization, signature, trustedOwnerKey: this.trustedOwnerKeys[r.principal_id],
        expectedChallenge: r.challenge, now: this.now() }),
    });
  }

  revoke(intentId, { revocation, signature }) {
    const row = this.store.get(intentId);
    if (!row) fail('UNKNOWN_INTENT');
    const sealed = parseSealedIntent(row.canonical);
    verifyRevocation({ sealed, revocation, signature, trustedOwnerKey: this.#ownerKey(sealed.intent.principalId) });
    return this.store.transition(intentId, ['PREPARED', 'AUTHORIZED'], 'REVOKED', { actor: 'owner', detail: { reason: 'owner revocation' } });
  }

  expireStale() {
    const now = this.now(); let n = 0;
    for (const r of this.store.listByState(['PREPARED', 'AUTHORIZED'])) {
      if (now >= Date.parse(r.expires_at)) { try { this.store.transition(r.intent_id, r.state, 'EXPIRED'); n++; } catch {} }
    }
    return n;
  }

  // ---- 3. execution (anyone may request; only an owner-authorized intent can proceed) ----
  async execute(intentId, { actor = 'service' } = {}) {
    if (!this.executor) fail('NO_EXECUTOR');
    const row = this.store.get(intentId);
    if (!row) fail('UNKNOWN_INTENT');
    if (row.state !== 'AUTHORIZED') fail(row.state === 'PREPARED' ? 'NOT_AUTHORIZED' : 'NOT_EXECUTABLE', row.state);
    const sealed = parseSealedIntent(row.canonical);
    let expired = false;
    try {
      this.store.transition(intentId, 'AUTHORIZED', 'RESERVED', {
        actor, detail: { capability: 'consumed', amountYocto: sealed.intent.amountYocto, recipient: sealed.intent.recipientId },
        guard: (r, db) => {
          if (r.digest !== sealed.digest) fail('STORED_INTENT_CORRUPT');
          const now = this.now();
          if (now >= Date.parse(sealed.intent.expiresAt)) { expired = true; fail('INTENT_EXPIRED'); }
          try {
            verifyAuthorization({ sealed, authorization: r.authz, signature: r.authz_sig, trustedOwnerKey: this.trustedOwnerKeys[r.principal_id],
              expectedChallenge: r.challenge, now });
          } catch (e) { if (e.code === 'AUTHZ_EXPIRED') expired = true; throw e; }
          const m = this.#checkMandate(this.store.getMandate(r.mandate_id), sealed.intent, now);
          SafeBoxStore.reserveMandateSpend(db, r.mandate_id, sealed.intent.amountYocto, m.maxTotalYocto);
        },
      });
    } catch (e) {
      if (expired) { try { this.store.transition(intentId, 'AUTHORIZED', 'EXPIRED', { actor, detail: { reason: e.code } }); } catch {} }
      throw e;
    }
    return this.#signAndSubmit(intentId, actor);
  }

  async #signAndSubmit(intentId, actor) {
    let built;
    try {
      built = await this.executor.buildSigned(this.store, intentId);
    } catch (e) {
      if (e instanceof SafeBoxError && DETERMINISTIC_PRESIGN.test(e.code)) {
        this.#finish(intentId, 'RESERVED', 'FAILED', { effect: { kind: 'NONE', reason: 'rejected before signing: ' + e.code }, release: true, actor });
      } else {
        this.store.note(intentId, actor, { event: 'PRESIGN_TRANSIENT_ERROR', error: e.code ?? e.name ?? 'Error' });
      }
      throw e;
    }
    this.store.transition(intentId, 'RESERVED', 'SIGNED', {
      actor: 'executor',
      patch: { tx_hash: built.txHash, signed_tx_b64: built.signedTxB64, signer_public_key: built.signerPublicKey,
        signer_nonce: built.signerNonce, signed_at: this.#iso() },
      detail: { txHash: built.txHash, signerNonce: built.signerNonce, signerPublicKey: built.signerPublicKey, blockHash: built.blockHash, keyKind: built.keyKind },
      guard: (r) => { if (r.tx_hash) fail('ALREADY_SIGNED'); },
    });
    return this.#broadcast(intentId);
  }

  async #broadcast(intentId) {
    const row = this.store.get(intentId);
    this.store.bumpBroadcast(intentId);
    try {
      await this.executor.broadcast(row.signed_tx_b64);
      this.store.transition(intentId, ['SIGNED', 'SUBMITTED', 'UNKNOWN'], 'SUBMITTED', { actor: 'executor', detail: { rpc: 'send_tx accepted (not proof of effect)' } });
    } catch (e) {
      if (process.env.SAFEBOX_DEBUG) console.error(e);
      this.store.transition(intentId, ['SIGNED', 'SUBMITTED', 'UNKNOWN'], 'UNKNOWN', { actor: 'executor', detail: { rpc: 'send_tx error', error: e.code ?? e.name } });
    }
    return this.reconcile(intentId);
  }

  #finish(intentId, from, to, { effect, evidence = null, release = false, actor = 'verifier', detail = {} }) {
    return this.store.transition(intentId, from, to, {
      actor, detail: { ...detail, effect },
      patch: { effect: JSON.stringify(effect), outcome: evidence ? JSON.stringify(evidence) : null, released: release ? 1 : 0 },
      guard: (r, db) => { if (release) SafeBoxStore.releaseMandateSpend(db, r.mandate_id, parseSealedIntent(r.canonical).intent.amountYocto); },
    });
  }

  // ---- 4. independent verification / reconciliation (never re-signs) ----
  async reconcile(intentId, { rebroadcast = false } = {}) {
    const row = this.store.get(intentId);
    if (!row) fail('UNKNOWN_INTENT');
    if (!['SIGNED', 'SUBMITTED', 'UNKNOWN'].includes(row.state)) return this.publicStatus(intentId);
    const sealed = parseSealedIntent(row.canonical);
    const i = sealed.intent;
    let status;
    try { status = await this.rpc.txStatus(row.tx_hash, i.signerAccountId); }
    catch (e) {
      this.store.note(intentId, 'verifier', { event: 'RECONCILE_RPC_ERROR', error: e.code ?? e.name });
      if (row.state === 'SIGNED') this.store.transition(intentId, 'SIGNED', 'UNKNOWN', { actor: 'verifier', detail: { reason: 'status unavailable' } });
      return this.publicStatus(intentId);
    }
    if (status) {
      const v = verifyTxOutcome({ sealed, row, status, nowIso: this.#iso(),
        expectedArgsB64: i.action === ACTIONS.CONTRACT ? contractArgsBytes(row).toString('base64') : undefined });
      if (this.rpc.simulated) Object.assign(v.evidence, { simulated: true, network: 'SIMULATED (offline test double, not NEAR testnet)', explorerUrl: null });
      if (v.verdict === 'CONFIRMED') this.#finish(intentId, row.state, 'CONFIRMED', { effect: v.effect, evidence: { ...v.evidence, checks: v.checks } });
      else if (v.verdict === 'FAILED') this.#finish(intentId, row.state, 'FAILED', { effect: v.effect, evidence: { ...v.evidence, checks: v.checks }, release: true });
      else if (v.verdict === 'PENDING') this.store.transition(intentId, row.state, row.state === 'SIGNED' ? 'SUBMITTED' : row.state, { actor: 'verifier', detail: { finality: v.evidence.finalExecutionStatus } });
      else this.store.transition(intentId, row.state, 'UNKNOWN', { actor: 'verifier', detail: { alert: 'ON_CHAIN_MISMATCH', checks: v.checks.filter(c => !c.ok) } });
      return this.publicStatus(intentId);
    }
    // Transaction not known to the node. Decide only from authoritative state.
    let ak;
    try { ak = await this.rpc.accessKey(i.signerAccountId, row.signer_public_key); }
    catch (e) { this.store.note(intentId, 'verifier', { event: 'RECONCILE_RPC_ERROR', error: e.code ?? e.name }); return this.publicStatus(intentId); }
    if (ak.nonce >= BigInt(row.signer_nonce)) {
      // Access-key nonce has reached our nonce: this exact transaction can never be included later.
      let proven = false, why;
      if (i.action === ACTIONS.CONTRACT) {
        const used = await this.rpc.viewFunction(i.receiverId, 'is_nonce_used', { nonce: i.nonce });
        proven = used === false; why = used ? 'intent nonce IS used on-chain but tx not found: needs archival lookup' : 'contract reports intent nonce unused';
      } else {
        proven = this.now() - Date.parse(row.signed_at) < NOT_INCLUDED_GRACE_MS;
        why = proven ? 'recently signed tx unknown to node and access-key nonce superseded' : 'old tx: node may have garbage-collected it; use an archival RPC';
      }
      if (proven && i.action === ACTIONS.CONTRACT && this.#canResign(row, i)) {
        // Proven never-includable AND the contract's one-use nonce is unused: a fresh transaction for the
        // SAME owner authorization cannot cause a second payment (the contract consumes the intent nonce).
        this.store.transition(intentId, row.state, 'RESERVED', { actor: 'verifier',
          patch: { tx_hash: null, signed_tx_b64: null, signer_nonce: null, signed_at: null },
          detail: { event: 'RESIGN_AFTER_PROOF_NOT_INCLUDED', supersededTxHash: row.tx_hash, why } });
        return this.#signAndSubmit(intentId, 'reconciler');
      }
      if (proven) { this.#finish(intentId, row.state, 'FAILED', { effect: { kind: 'NONE', reason: 'NOT_INCLUDED: ' + why }, release: true }); return this.publicStatus(intentId); }
      this.store.transition(intentId, row.state, 'UNKNOWN', { actor: 'verifier', detail: { reason: why } });
      return this.publicStatus(intentId);
    }
    if (row.state !== 'UNKNOWN') this.store.transition(intentId, row.state, 'UNKNOWN', { actor: 'verifier', detail: { reason: 'tx not found; nonce not consumed' } });
    if (rebroadcast) {
      // Re-sending the IDENTICAL signed bytes is idempotent (same hash, same access-key nonce). Never re-sign.
      this.store.note(intentId, 'verifier', { event: 'REBROADCAST_IDENTICAL_SIGNED_TX', txHash: row.tx_hash });
      return this.#broadcast(intentId);
    }
    return this.publicStatus(intentId);
  }

  #canResign(row, i) {
    const now = this.now();
    if (now >= Date.parse(i.expiresAt)) return false;
    try { return now < Date.parse(JSON.parse(row.authz).expiresAt) - 30_000; } catch { return false; }
  }

  /** Crash/restart recovery. Never creates a second transaction for an intent. */
  async recover({ rebroadcast = true } = {}) {
    const report = [];
    this.expireStale();
    for (const r of this.store.listByState(['RESERVED'])) {
      // RESERVED without a persisted signed tx means nothing was ever broadcast: signing may resume.
      // (A tx is broadcast only after its bytes are durably stored in state SIGNED.)
      try { await this.#signAndSubmit(r.intent_id, 'recovery'); } catch (e) { /* recorded in journal */ }
      report.push({ intentId: r.intent_id, from: 'RESERVED', to: this.store.get(r.intent_id).state });
    }
    for (const r of this.store.listByState(['SIGNED', 'SUBMITTED', 'UNKNOWN'])) {
      await this.reconcile(r.intent_id, { rebroadcast });
      report.push({ intentId: r.intent_id, from: r.state, to: this.store.get(r.intent_id).state });
    }
    return report;
  }

  publicStatus(intentId) {
    const r = this.store.get(intentId);
    if (!r) fail('UNKNOWN_INTENT');
    return {
      intentId, state: r.state, digest: r.digest, txHash: r.tx_hash ?? null,
      effect: r.effect ? JSON.parse(r.effect) : null,
      evidence: r.outcome ? JSON.parse(r.outcome) : null,
      verifiedComplete: r.state === 'CONFIRMED',
    };
  }
}
