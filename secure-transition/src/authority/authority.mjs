// Independent Security Authority (model of the V6 Root + Vault policy semantics, NOT the V6 code).
// Holds the account signing key and the protected policy. It never accepts a policy, credential, counter or trust-anchor
// change because an application version changed: only owner-signed governance commands change them. Every request from
// any application version is checked against the same policy.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readJson, writeJsonDurable } from '../common/fsutil.mjs';
import { signEnvelope, verifyEnvelope, DOMAINS, digestObj, keyIdOf } from '../common/crypto.mjs';
import { crashPoint } from '../common/faults.mjs';

export class AuthorityError extends Error { constructor(code, detail) { super(code + (detail ? `: ${detail}` : '')); this.code = code; } }
const fail = (code, detail) => { throw new AuthorityError(code, detail); };
const big = (s) => { if (typeof s !== 'string' || !/^[0-9]{1,30}$/.test(s)) fail('BAD_AMOUNT'); return BigInt(s); };
const REQ_ID = /^[A-Za-z0-9-]{8,64}$/;
const MAX_REFUSALS = 500;

// Which roles must co-sign each owner command type.
const QUORUM = {
  AUTHORIZE_UPDATE: [['owner']],
  APPROVE_PAYMENT: [['owner']],
  APPROVE_UPDATE_ROOT: [['owner', 'recovery']],
  SET_WITNESS: [['owner', 'recovery']],
  POLICY_MIGRATION: null, // owner for restrictive, owner+recovery for permissive (decided per body)
  FREEZE: [['owner'], ['recovery']],
  UNFREEZE: [['owner', 'recovery']],
  ROTATE_OWNER: [['recovery']],
  END_SAFE_HOLD: [['owner', 'recovery']],
};

export function policyOf(s) {
  return { schema: s.schema, purpose: s.purpose, owner: s.owner, recovery: s.recovery, approvedRoots: s.approvedRoots, witnessPub: s.witnessPub, account: s.account };
}
export const policyDigest = (s) => digestObj(policyOf(s));

export function initialState({ accountId, accountPub, ownerPub, recoveryPub, witnessPub, purpose, release, approvedRoots = [] }) {
  return {
    schema: 1, epoch: 1, account: { id: accountId, pub: accountPub },
    owner: { keys: [ownerPub], revoked: [] }, recovery: { keys: [recoveryPub] },
    purpose, spent: '0', nextNonce: 1, payments: {}, consumedOwnerNonces: {},
    frozen: null, maintenance: null, safeHold: null,
    release, versionFloor: release.version, pendingUpdate: null, approvedRoots, witnessPub,
    refusals: [], refusalCount: 0, securityEvents: 0,
  };
}

export class Authority {
  /** ledger: async (method, params) => response. now: () => ms */
  constructor({ dir, ledger, now = () => Date.now() }) {
    this.dir = dir; this.ledger = ledger; this.now = now;
    this.statePath = join(dir, 'state.json');
    this.s = readJson(this.statePath);
    if (!this.s) fail('NO_STATE');
  }
  save() { writeJsonDurable(this.statePath, this.s); }
  key() { return readFileSync(join(this.dir, 'account.key'), 'utf8'); }

  refuse(source, method, code) {
    this.s.refusalCount++;
    this.s.refusals.push({ at: new Date(this.now()).toISOString(), source, method, code, maintenance: this.s.maintenance?.transitionId ?? null });
    if (this.s.refusals.length > MAX_REFUSALS) this.s.refusals.shift();
    this.save();
  }

  status() {
    const s = this.s;
    return {
      schema: s.schema, epoch: s.epoch, policyDigest: policyDigest(s), purpose: s.purpose, spent: s.spent, nextNonce: s.nextNonce,
      frozen: s.frozen, maintenance: s.maintenance, safeHold: s.safeHold, release: s.release, versionFloor: s.versionFloor,
      pendingUpdate: s.pendingUpdate, approvedRoots: s.approvedRoots, witnessKeyId: keyIdOf(s.witnessPub),
      ownerKeyIds: s.owner.keys.map(keyIdOf), revokedOwnerKeyIds: s.owner.revoked.map(keyIdOf), consumedOwnerNonces: Object.keys(s.consumedOwnerNonces).length,
      payments: Object.fromEntries(Object.entries(s.payments).map(([k, p]) => [k, { to: p.to, amount: p.amount, nonce: p.nonce, txid: p.txid, status: p.status }])),
      refusalCount: s.refusalCount, securityEvents: s.securityEvents,
    };
  }
  refusalsSince(transitionId) { return this.s.refusals.filter(r => r.maintenance === transitionId && r.source === 'app'); }

  // ---------------- owner governance ----------------
  /** cmd: { envs: [envelope...] } all over the same payload { type, body, nonce, epoch, expiresAt, account }. */
  verifyOwner(cmd, expectType) {
    const envs = cmd?.envs;
    if (!Array.isArray(envs) || !envs.length || envs.length > 4) fail('OWNER_SIGNATURE_REQUIRED');
    const p = envs[0].payload;
    if (!p || typeof p !== 'object' || (expectType && p.type !== expectType)) fail('OWNER_COMMAND_TYPE');
    if (!(p.type in QUORUM)) fail('OWNER_COMMAND_UNKNOWN', p.type);
    const pd = digestObj(p);
    const roles = new Set();
    for (const e of envs) {
      if (digestObj(e.payload) !== pd) fail('OWNER_COMMAND_PAYLOAD_MISMATCH');
      if (e.domain === DOMAINS.OWNER && verifyEnvelope(e, DOMAINS.OWNER, this.s.owner.keys)) roles.add('owner');
      else if (e.domain === DOMAINS.RECOVERY && verifyEnvelope(e, DOMAINS.RECOVERY, this.s.recovery.keys)) roles.add('recovery');
      else if (e.domain === DOMAINS.OWNER && verifyEnvelope(e, DOMAINS.OWNER, this.s.owner.revoked)) fail('OWNER_CREDENTIAL_REVOKED');
      else fail('OWNER_SIGNATURE_INVALID');
    }
    if (p.account !== this.s.account.id) fail('OWNER_COMMAND_WRONG_ACCOUNT');
    if (p.epoch !== this.s.epoch) fail('OWNER_COMMAND_STALE_EPOCH', `${p.epoch} != ${this.s.epoch}`);
    if (!(Number(p.expiresAt) > this.now())) fail('OWNER_COMMAND_EXPIRED');
    if (typeof p.nonce !== 'string' || p.nonce.length < 16) fail('OWNER_COMMAND_NONCE');
    if (this.s.consumedOwnerNonces[p.nonce]) fail('OWNER_COMMAND_REPLAYED');
    const quorum = p.type === 'POLICY_MIGRATION' ? (this.isPermissive(p.body) ? [['owner', 'recovery']] : [['owner']]) : QUORUM[p.type];
    if (!quorum.some(q => q.every(r => roles.has(r)))) fail('OWNER_QUORUM_NOT_MET', `${p.type} needs ${JSON.stringify(quorum)}`);
    return p;
  }
  consume(p) { this.s.consumedOwnerNonces[p.nonce] = p.type; }

  isPermissive(body) {
    const cur = this.s.purpose; const nxt = body?.purpose;
    if (body?.schema !== undefined && body.schema !== this.s.schema) return true;
    if (!nxt) return false;
    if ((nxt.recipients ?? []).some(r => !cur.recipients.includes(r))) return true;
    try { if (big(nxt.perTxMax) > big(cur.perTxMax) || big(nxt.budget) > big(cur.budget)) return true; } catch { return true; }
    return false;
  }

  ownerCommand(cmd) {
    const p = this.verifyOwner(cmd);
    const s = this.s; const b = p.body ?? {};
    switch (p.type) {
      case 'FREEZE': s.frozen = { at: this.now(), reason: String(b.reason ?? 'owner').slice(0, 120) }; break;
      case 'UNFREEZE': s.frozen = null; break;
      case 'ROTATE_OWNER': {
        if (typeof b.newOwnerPub !== 'string' || !b.newOwnerPub.includes('PUBLIC KEY')) fail('BAD_KEY');
        s.owner.revoked.push(...s.owner.keys); s.owner.keys = [b.newOwnerPub]; s.epoch++; break;
      }
      case 'AUTHORIZE_UPDATE': {
        if (s.maintenance) fail('TRANSITION_IN_PROGRESS');
        if (!Number.isSafeInteger(b.version) || b.version <= s.versionFloor) fail('VERSION_BELOW_FLOOR', `${b.version} <= ${s.versionFloor}`);
        if (!/^[0-9a-f]{64}$/.test(b.sha256 ?? '') || !Number.isSafeInteger(b.length) || typeof b.targetName !== 'string') fail('BAD_UPDATE_AUTHORIZATION');
        s.pendingUpdate = { targetName: b.targetName, version: b.version, sha256: b.sha256, length: b.length, nonce: p.nonce, authorizedAt: this.now() };
        break;
      }
      case 'APPROVE_UPDATE_ROOT': {
        if (!/^[0-9a-f]{64}$/.test(b.rootDigest ?? '')) fail('BAD_ROOT_DIGEST');
        if (!s.approvedRoots.includes(b.rootDigest)) s.approvedRoots.push(b.rootDigest);
        s.epoch++; break;
      }
      case 'SET_WITNESS': s.witnessPub = String(b.witnessPub); s.epoch++; break;
      case 'POLICY_MIGRATION': {
        if (b.fromPolicyDigest !== policyDigest(s)) fail('POLICY_MIGRATION_STALE');
        if (b.purpose) {
          const np = b.purpose;
          if (!(Number.isSafeInteger(np.version) && np.version > s.purpose.version) || !Array.isArray(np.recipients)) fail('POLICY_MIGRATION_BAD_PURPOSE');
          big(np.perTxMax); big(np.budget);
          s.purpose = { id: String(np.id ?? s.purpose.id), version: np.version, recipients: np.recipients.map(String), perTxMax: np.perTxMax, budget: np.budget };
        }
        if (b.schema !== undefined) { if (!Number.isSafeInteger(b.schema) || b.schema <= s.schema) fail('SCHEMA_DOWNGRADE'); s.schema = b.schema; }
        s.epoch++; break;
      }
      case 'END_SAFE_HOLD': {
        if (!s.safeHold) fail('NOT_IN_SAFE_HOLD');
        if (b.transitionId !== s.safeHold.transitionId) fail('SAFE_HOLD_ID_MISMATCH');
        s.safeHold = null; s.maintenance = null; break;
      }
      default: fail('OWNER_COMMAND_UNKNOWN');
    }
    this.consume(p); this.save();
    return { ok: true, type: p.type, epoch: s.epoch };
  }

  // ---------------- payments (any application version) ----------------
  async pay({ requestId, to, amount, approval }) {
    const s = this.s;
    if (typeof requestId !== 'string' || !REQ_ID.test(requestId)) fail('BAD_REQUEST_ID');
    if (typeof to !== 'string' || !/^[a-z0-9._-]{2,64}$/.test(to)) fail('BAD_RECIPIENT');
    const amt = big(amount); if (amt <= 0n) fail('BAD_AMOUNT');
    const prev = s.payments[requestId];
    if (prev) {
      if (prev.to !== to || prev.amount !== amount) fail('REQUEST_ID_REUSED');
      return { ok: true, idempotent: true, txid: prev.txid, status: prev.status };
    }
    if (s.frozen) fail('FREEZE_ACTIVE');
    if (s.safeHold) fail('SAFE_HOLD');
    if (s.maintenance) fail('MAINTENANCE_ACTIVE');
    const within = s.purpose.recipients.includes(to) && amt <= big(s.purpose.perTxMax) && big(s.spent) + amt <= big(s.purpose.budget);
    let ownerApproved = false; let ap = null;
    if (!within) {
      if (!approval) fail('OWNER_APPROVAL_REQUIRED');
      ap = this.verifyOwner(approval, 'APPROVE_PAYMENT');
      const b = ap.body ?? {};
      if (b.requestId !== requestId || b.to !== to || b.amount !== amount) fail('APPROVAL_BINDING_MISMATCH');
      ownerApproved = true;
    }
    const nonce = s.nextNonce;
    const tx = { from: s.account.id, to, amount, nonce, memo: requestId };
    const env = signEnvelope(DOMAINS.LEDGER_TX, tx, this.key(), s.account.pub);
    const txid = digestObj(tx);
    if (ap) this.consume(ap);
    s.payments[requestId] = { requestId, to, amount, nonce, txid, env, status: 'SIGNED', ownerApproved, at: this.now() };
    s.spent = (big(s.spent) + amt).toString(); s.nextNonce = nonce + 1;
    this.save();
    crashPoint('authority.after-sign-persist');
    let status = 'SIGNED';
    try { const r = await this.ledger('submit', { env }); if (r.ok) status = r.status === 'SETTLED' ? 'SETTLED' : 'BROADCAST'; } catch { /* offline: reconcile rebroadcasts */ }
    if (s.payments[requestId].status === 'SIGNED') { s.payments[requestId].status = status; this.save(); }
    return { ok: true, txid, status };
  }

  // ---------------- transition controller interface (ctl socket only) ----------------
  beginMaintenance({ transitionId }) {
    const s = this.s;
    if (typeof transitionId !== 'string' || transitionId.length < 8) fail('BAD_TRANSITION_ID');
    if (s.safeHold) fail('SAFE_HOLD');
    if (s.maintenance && s.maintenance.transitionId !== transitionId) fail('TRANSITION_IN_PROGRESS');
    if (!s.maintenance) { s.maintenance = { transitionId, since: this.now(), reconciled: false, startPolicyDigest: policyDigest(s), startEpoch: s.epoch }; this.save(); }
    return { ok: true, maintenance: s.maintenance };
  }
  enterSafeHold({ transitionId, reason }) {
    const s = this.s;
    if (!s.maintenance || s.maintenance.transitionId !== transitionId) fail('NOT_THIS_TRANSITION');
    if (!s.safeHold) { s.safeHold = { transitionId, reason: String(reason).slice(0, 200), at: this.now() }; s.securityEvents++; this.save(); }
    return { ok: true, safeHold: s.safeHold };
  }
  /** Reconcile with the authoritative ledger after reconnection. */
  async reconcile({ transitionId }) {
    const s = this.s;
    if (!s.maintenance || s.maintenance.transitionId !== transitionId) fail('NOT_THIS_TRANSITION');
    const report = { settled: [], pending: [], rebroadcast: [], failed: [], unknownLedgerTx: [] };
    for (const p of Object.values(s.payments)) {
      if (p.status === 'SETTLED' || p.status.startsWith('FAILED')) continue;
      const st = await this.ledger('status', { txid: p.txid });
      if (st.status === 'UNKNOWN') { await this.ledger('submit', { env: p.env }); p.status = 'BROADCAST'; report.rebroadcast.push(p.requestId); }
      else if (st.status === 'PENDING') { p.status = 'BROADCAST'; report.pending.push(p.requestId); }
      else { p.status = st.status; (st.status === 'SETTLED' ? report.settled : report.failed).push(p.requestId); }
    }
    const known = new Set(Object.values(s.payments).map(p => p.txid));
    const hist = await this.ledger('history', { from: s.account.id });
    for (const h of hist.history ?? []) if (!known.has(h.txid)) report.unknownLedgerTx.push(h.txid);
    const acct = await this.ledger('account', { id: s.account.id });
    if (acct.account && acct.account.nonce >= s.nextNonce) report.unknownLedgerTx.push(`nonce:${acct.account.nonce}`);
    if (report.unknownLedgerTx.length) {
      // The ledger shows activity our Authority never signed: the account key is compromised. Fail closed.
      s.frozen = { at: this.now(), reason: 'KEY_COMPROMISE_SUSPECTED' }; s.securityEvents++;
      s.safeHold = { transitionId, reason: 'KEY_COMPROMISE_SUSPECTED', at: this.now() };
      this.save();
      return { ok: false, error: 'KEY_COMPROMISE_SUSPECTED', report };
    }
    s.maintenance.reconciled = true; s.maintenance.reconciledAt = this.now();
    this.save();
    return { ok: true, report };
  }
  /** End maintenance. Needs a witness READY attestation bound to this transition and to the release now active. */
  completeTransition({ transitionId, attestation }) {
    const s = this.s; const m = s.maintenance;
    if (!m || m.transitionId !== transitionId) fail('NOT_THIS_TRANSITION');
    if (s.safeHold) fail('SAFE_HOLD');
    if (!m.reconciled) fail('RECONCILE_REQUIRED');
    if (!verifyEnvelope(attestation, DOMAINS.WITNESS, [s.witnessPub])) fail('WITNESS_ATTESTATION_INVALID');
    const a = attestation.payload;
    if (a.kind !== 'READY' || a.transitionId !== transitionId) fail('WITNESS_ATTESTATION_MISMATCH');
    if (a.policyDigest !== policyDigest(s) || a.epoch !== s.epoch) fail('WITNESS_STATE_MISMATCH');
    if (a.rolledBack) {
      if (a.release.version !== s.release.version || a.release.sha256 !== s.release.sha256) fail('ROLLBACK_RELEASE_MISMATCH');
    } else {
      const pu = s.pendingUpdate;
      if (!pu || a.release.version !== pu.version || a.release.sha256 !== pu.sha256) fail('RELEASE_NOT_OWNER_AUTHORIZED');
      if (pu.version <= s.versionFloor) fail('VERSION_BELOW_FLOOR');
      s.versionFloor = pu.version; s.release = { version: pu.version, sha256: pu.sha256 }; s.pendingUpdate = null;
    }
    s.maintenance = null; this.save();
    return { ok: true, release: s.release, versionFloor: s.versionFloor };
  }
}
