// SafeBox V3 Execution Vault (extends the V2-B Sensitive Zone semantics).
// Authority comes ONLY from (a) the vault's own, independently replayed replica of the Purpose Root chain and (b) a
// K1/K2 payment capability with a WebAuthn UV assertion over its exact digest. The vault never accepts a Root state it
// cannot verify itself: a compromised Root service can stall it (fail closed), not steer it.
// Preserved from V2-B: exact-amount payments (F-B01), buffered release with a release-time re-check, cumulative budget
// controls, freeze/HOLD semantics (frozen payments are cancelled, never auto-released), durable signed bytes before
// submission, idempotent ledger submission, hash-chained journal in the same transaction as every state change.
import { randomBytes, randomUUID } from 'node:crypto';
import { fail, SafeBoxError, iso, exactFields } from '../common/canon.mjs';
import { V2_DOMAINS, digestOf } from '../../v2/common/crypto.mjs';
import { LEDGER_TX_VERSION } from '../../v2/mock-ledger/ledger.mjs';
import { SensitiveStore } from '../../v2/sensitive/store.mjs';
import * as V3CHAIN from '../root/chain.mjs';
import { verifyPaycap } from './paycap.mjs';
import { purposeViolations } from '../root/capsule.mjs';

const MEMO_OK = (m) => typeof m === 'string' && m.length <= 280 && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(m);
const memoAscii = (m) => JSON.stringify(m).replace(/[\u0080-￿]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
const LEDGER_DEFINITIVE = /^LEDGER_(BAD_TX|BAD_SIGNATURE|UNSUPPORTED_ASSET|WRONG_SENDER|AMOUNT_OVER_CAP|UNKNOWN_RECIPIENT|SELF_TRANSFER|INSUFFICIENT_FUNDS)$/;
const HOLDING = ['RESERVED', 'BUFFERED', 'RELEASED', 'UNKNOWN', 'FROZEN'];

const EXTRA = `
CREATE TABLE IF NOT EXISTS root_chain (seq INTEGER PRIMARY KEY, tr TEXT NOT NULL, head TEXT NOT NULL, first_seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS root_alarms (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, code TEXT NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS cap_evidence (cap_id TEXT PRIMARY KEY, payment_id TEXT NOT NULL UNIQUE, cap TEXT NOT NULL, approval TEXT NOT NULL,
  cred_id TEXT NOT NULL, epoch INTEGER NOT NULL, purpose_version TEXT NOT NULL, sku TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS sign_floor (cred_id TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS root_chain_no_update BEFORE UPDATE ON root_chain BEGIN SELECT RAISE(ABORT, 'root replica is append-only'); END;
CREATE TRIGGER IF NOT EXISTS root_chain_no_delete BEFORE DELETE ON root_chain BEGIN SELECT RAISE(ABORT, 'root replica is append-only'); END;
CREATE TRIGGER IF NOT EXISTS cap_evidence_no_delete BEFORE DELETE ON cap_evidence BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
`;

export class ExecutionVault {
  /**
   * cfg (trusted, written by the launcher): { genesis, pinnedChainId, executorAccount, minBufferMs, leaseMs, bufferMs }
   * deps: { store: SensitiveStore, now, wallNow, executorSigner (V2 signer), ledger (client) }
   */
  constructor(cfg, { store, now, wallNow = () => Date.now(), executorSigner, ledger }) {
    this.cfg = Object.freeze({ minBufferMs: 600_000, bufferMs: 600_000, leaseMs: 5_000, ...cfg });
    this.C = cfg.chain ?? V3CHAIN; // protocol state machine the vault replays itself (V3 default, V4 passes its own)
    if (this.cfg.bufferMs < this.cfg.minBufferMs) fail('BUFFER_BELOW_FLOOR');
    this.store = store; this.now = now; this.wallNow = wallNow; this.executor = executorSigner; this.ledger = ledger;
    this.store.db.exec(EXTRA);
    this.leaseUntil = 0; this.busy = false;
    this.#rebuild();
  }

  // ------------------------------------------------ Root replica (independent verification)
  #rebuild() {
    let st = this.C.genesisState(this.cfg.genesis, { pinnedChainId: this.cfg.pinnedChainId });
    for (const r of this.store.db.prepare('SELECT * FROM root_chain ORDER BY seq').all()) {
      st = this.C.applyTransition(st, JSON.parse(r.tr)).state; // a tampered replica fails here: the vault refuses to start
      if (st.head !== r.head) fail('ROOT_REPLICA_CORRUPT');
    }
    this.root = st;
  }
  rootAlarm() { return this.store.db.prepare('SELECT COUNT(*) n FROM root_alarms').get().n > 0; }
  #alarm(code, detail) {
    this.store.db.prepare('INSERT INTO root_alarms (at, code, detail) VALUES (?,?,?)').run(this.now(), code, String(detail ?? '').slice(0, 300));
  }
  /** Ingest Root transitions (from the Root service — an UNTRUSTED transport for this purpose). */
  syncRoot(transitions) {
    if (!Array.isArray(transitions)) fail('BAD_SYNC');
    const out = { applied: 0, effects: [], alarm: null };
    for (const t of transitions) {
      const seq = Number(t?.seq);
      if (Number.isSafeInteger(seq) && seq <= this.root.seq) {
        const have = this.store.db.prepare('SELECT tr FROM root_chain WHERE seq=?').get(seq);
        if (have && have.tr !== JSON.stringify(t)) { this.#alarm('ROOT_FORK_OR_ROLLBACK', `seq ${seq}`); out.alarm = 'ROOT_FORK_OR_ROLLBACK'; return out; }
        continue;
      }
      let r;
      try { r = this.C.applyTransition(this.root, t); }
      catch (e) { this.#alarm('ROOT_TRANSITION_REJECTED', `${t?.action?.type}:${e.code ?? e.message}`); out.alarm = 'ROOT_TRANSITION_REJECTED:' + (e.code ?? 'ERR'); return out; }
      if (Date.parse(t.at) > this.now() + Number(this.root.config.skewMs)) { this.#alarm('ROOT_TIME_AHEAD', t.seq); out.alarm = 'ROOT_TIME_AHEAD'; return out; }
      this.store.tx(() => {
        this.store.db.prepare('INSERT INTO root_chain (seq, tr, head, first_seen) VALUES (?,?,?,?)').run(Number(t.seq), JSON.stringify(t), r.state.head, this.now());
        this.store.journal(null, null, null, 'root-replica', { event: 'ROOT_TRANSITION', seq: t.seq, type: t.action.type, effects: r.effects.map(e => e.type) });
        this.root = r.state;
        this.#onRootEffects(r.effects);
      });
      out.applied++; out.effects.push(...r.effects);
    }
    return out;
  }
  #onRootEffects(effects) {
    const types = new Set(effects.map(e => e.type));
    const buffered = () => this.store.byState(['BUFFERED']);
    const meta = (pid) => this.store.db.prepare('SELECT * FROM cap_evidence WHERE payment_id=?').get(pid);
    if (types.has('FROZEN') || types.has('EMERGENCY_LOCKDOWN') || types.has('INSUFFICIENT_AUTHORITY')) {
      for (const r of buffered()) this.store.move(r.payment_id, 'BUFFERED', 'FROZEN', 'root', { reason: 'root freeze/lockdown' }, { reason: 'ROOT_FROZEN' });
    }
    for (const r of buffered()) {
      const m = meta(r.payment_id); const c = this.root.creds[m.cred_id];
      let why = null;
      if (m.epoch !== this.root.epoch) why = 'STALE_EPOCH';
      else if (m.purpose_version !== this.root.purpose.version) why = 'STALE_PURPOSE_VERSION';
      else if (!c || c.status !== 'active') why = 'APPROVER_CREDENTIAL_' + (c?.status ?? 'UNKNOWN').toUpperCase();
      if (why) this.store.move(r.payment_id, 'BUFFERED', 'CANCELLED', 'root', { reason: why }, { reason: why });
    }
    if ((types.has('UNFROZEN') || types.has('RECOVERY_CLOSED')) && !this.root.freeze.active && !this.root.lockdown.active && this.store.control().level === 'NONE') {
      // V2 semantics: frozen payments are never auto-released after an unfreeze; the owner re-issues if still wanted
      for (const r of this.store.byState(['FROZEN'])) if (!r.tx_statement) this.store.move(r.payment_id, 'FROZEN', 'CANCELLED', 'root', { reason: 'cancelled on unfreeze' }, { reason: 'CANCELLED_AFTER_FREEZE' });
    }
  }
  view() { return { ...this.C.rootView(this.root), now: this.now() }; }

  #spent() {
    const rows = this.store.db.prepare(`SELECT amount, proposed_at FROM payments WHERE state IN (${[...HOLDING, 'SETTLED'].map(() => '?').join(',')})`).all(...HOLDING, 'SETTLED');
    const now = this.now(); let cum = 0n, day = 0n;
    for (const r of rows) { cum += BigInt(r.amount); if (r.proposed_at > now - 86_400_000) day += BigInt(r.amount); }
    return { cumulativeYocto: cum.toString(), last24hYocto: day.toString() };
  }
  #signFloor(credId) { return this.store.db.prepare('SELECT n FROM sign_floor WHERE cred_id=?').get(credId)?.n ?? 0; }

  // ------------------------------------------------ General Zone facing (untrusted caller)
  propose(args) {
    let v = null;
    try {
      exactFields(args, ['capability', 'approval', 'recipientId', 'amountYocto', 'asset', 'memo'], [], 'PROPOSE_FIELDS');
      if (!MEMO_OK(args.memo)) fail('INVALID_MEMO');
      if (this.rootAlarm()) fail('ROOT_INTEGRITY_ALARM');
      if (this.root.freeze.active) fail('FREEZE_ACTIVE');
      if (this.root.lockdown.active) fail('EMERGENCY_LOCKDOWN_ACTIVE');
      v = verifyPaycap(this.root, args, { now: this.now(), signCountFloor: (c) => this.#signFloor(c) });
      // exact request == exact capability (F-B01 generalised: recipient, amount and asset are all bound)
      if (args.recipientId !== v.cap.recipientId) fail('RECIPIENT_NOT_BOUND_TO_CAPABILITY');
      if (args.amountYocto !== v.cap.amountYocto) fail('AMOUNT_NOT_EXACT');
      if (args.asset !== v.cap.asset) fail('ASSET_NOT_BOUND');
    } catch (e) { this.store.decision('gz', 'PROPOSE', 'DENY', [e.code ?? 'INVALID'], v?.cap?.capId ?? null); throw e; }
    const cap = v.cap; const paymentId = 'p_' + randomUUID().replaceAll('-', ''); const now = this.now();
    const out = this.store.tx(() => {
      const control = this.store.control();
      const deny = [];
      if (control.level !== 'NONE') deny.push(control.level === 'FROZEN' ? 'FREEZE_ACTIVE' : 'HOLD_ACTIVE');
      if (this.store.db.prepare('SELECT 1 FROM caps_used WHERE cap_id=?').get(cap.capId)) deny.push('CAPABILITY_ALREADY_USED');
      if (this.store.db.prepare('SELECT 1 FROM cap_evidence WHERE nonce=?').get(cap.nonce)) deny.push('CAPABILITY_NONCE_REUSED');
      deny.push(...purposeViolations(this.root.purpose, { operation: cap.operation, recipientId: cap.recipientId, asset: cap.asset, amountYocto: cap.amountYocto,
        sku: cap.sku === '-' ? null : cap.sku, now, capExpiresAt: v.expiresAt, capIssuedAt: v.issuedAt }, this.#spent()));
      const pend = this.store.byState(['RESERVED', 'BUFFERED', 'RELEASED', 'UNKNOWN']).length;
      if (pend + 1 > 16) deny.push('PENDING_COUNT_LIMIT');
      deny.push(...this.extraProposeDenials({ credId: v.credId })); // subclass capacity rules (V5.1: incident-flow cap); none in V3
      if (deny.length) return { denied: deny };
      this.store.db.prepare(`INSERT INTO payments (payment_id, cap_id, cap_digest, principal_id, policy_id, policy_digest, recipient, asset, amount,
        intent_nonce, state, proposed_at, cap_expires_at, memo, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?, 'PROPOSED', ?,?,?,?)`)
        .run(paymentId, cap.capId, v.digestHex, this.root.accountId, this.root.purpose.purposeId, this.root.purposeDigest, cap.recipientId, cap.asset, cap.amountYocto,
          randomBytes(16).toString('hex'), now, v.expiresAt, memoAscii(args.memo), now);
      this.store.db.prepare('INSERT INTO cap_evidence (cap_id, payment_id, cap, approval, cred_id, epoch, purpose_version, sku, nonce) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(cap.capId, paymentId, JSON.stringify(cap), JSON.stringify(args.approval), v.credId, this.root.epoch, cap.purposeVersion, cap.sku, cap.nonce);
      if (v.signCount !== null) this.store.db.prepare('INSERT INTO sign_floor (cred_id, n) VALUES (?,?) ON CONFLICT(cred_id) DO UPDATE SET n=MAX(n, excluded.n)').run(v.credId, v.signCount);
      this.store.journal(paymentId, null, 'PROPOSED', 'general-zone', { capId: cap.capId, credId: v.credId, epoch: this.root.epoch, recipient: cap.recipientId, amount: cap.amountYocto });
      this.store.db.prepare('INSERT INTO caps_used (cap_id, payment_id) VALUES (?,?)').run(cap.capId, paymentId);
      this.store.move(paymentId, 'PROPOSED', 'AUTHORIZED', 'policy', { decision: 'ALLOW', rootHead: this.root.head, capDigest: v.digestHex });
      this.store.move(paymentId, 'AUTHORIZED', 'RESERVED', 'policy', { reservedYocto: cap.amountYocto });
      const row = this.store.move(paymentId, 'RESERVED', 'BUFFERED', 'policy', { releaseAt: now + this.cfg.bufferMs }, { release_at: now + this.cfg.bufferMs });
      return { row };
    });
    if (out.denied) { this.store.decision('gz', 'PROPOSE', 'DENY', out.denied, cap.capId); fail('POLICY_DENY', out.denied.join(',')); }
    this.store.decision('gz', 'PROPOSE', 'ALLOW', [], cap.capId, paymentId);
    return { paymentId, state: out.row.state, releaseAt: out.row.release_at };
  }

  extraProposeDenials() { return []; }
  status(paymentId) {
    if (typeof paymentId !== 'string' || !/^p_[0-9a-f]{32}$/.test(paymentId)) fail('INVALID_ID');
    const r = this.store.get(paymentId); if (!r) fail('UNKNOWN_PAYMENT');
    return { paymentId, state: r.state, recipient: r.recipient, amountYocto: r.amount, releaseAt: r.release_at, txId: r.tx_id, reason: r.reason };
  }

  // ------------------------------------------------ Supervisor facing
  heartbeat() { this.leaseUntil = this.wallNow() + this.cfg.leaseMs; return { leaseUntil: this.leaseUntil }; }
  setLevel(level, reason, classification) {
    if (!['HOLD', 'FROZEN'].includes(level)) fail('BAD_LEVEL');
    return this.store.tx(() => {
      const cur = this.store.control();
      if (cur.level === 'FROZEN' && level === 'HOLD') return { level: 'FROZEN' };
      if (cur.level !== level) {
        this.store.setControl('level', level); this.store.setControl('reason', String(reason).slice(0, 200)); this.store.setControl('since', String(this.now()));
        this.store.setControl('classification', String(classification).slice(0, 40));
        this.store.journal(null, null, null, 'supervisor', { event: level, reason, classification });
      }
      if (level === 'FROZEN') for (const r of this.store.byState(['BUFFERED'])) this.store.move(r.payment_id, 'BUFFERED', 'FROZEN', 'supervisor', { reason: 'emergency freeze' }, { reason: 'FROZEN' });
      return { level };
    });
  }
  clearHold(reviewRef) {
    return this.store.tx(() => { if (this.store.control().level !== 'HOLD') fail('NOT_ON_HOLD'); this.store.setControl('level', 'NONE'); this.store.journal(null, null, null, 'supervisor', { event: 'HOLD_CLEARED', reviewRef: String(reviewRef).slice(0, 64) }); return { level: 'NONE' }; });
  }
  /** The vault-local supervisor freeze lifts only when the ROOT chain shows the freeze lifted (owner quorum + repair certificate). */
  liftLocalFreeze() {
    return this.store.tx(() => {
      if (this.store.control().level !== 'FROZEN') fail('NOT_FROZEN');
      if (this.root.freeze.active || this.root.lockdown.active) fail('ROOT_STILL_FROZEN');
      if (!this.root.chainId) fail('NO_ROOT');
      const cancelled = [];
      for (const r of this.store.byState(['FROZEN'])) if (!r.tx_statement) { this.store.move(r.payment_id, 'FROZEN', 'CANCELLED', 'root', { reason: 'cancelled on unfreeze' }, { reason: 'CANCELLED_AFTER_FREEZE' }); cancelled.push(r.payment_id); }
      this.store.setControl('level', 'NONE'); this.store.journal(null, null, null, 'root', { event: 'LOCAL_FREEZE_LIFTED_BY_ROOT', head: this.root.head });
      return { level: 'NONE', cancelled };
    });
  }

  async tick() {
    if (this.busy) return { skipped: 'busy' };
    this.busy = true;
    try {
      const out = { released: [], settled: [], blocked: [], expired: [], failed: [], unknown: [], cancelled: [] };
      await this.reconcile(out);
      const now = this.now();
      for (const row of this.store.byState(['BUFFERED'])) {
        if (row.release_at > now) continue;
        const res = this.#releaseOne(row.payment_id);
        if (res.blocked) { out.blocked.push({ paymentId: row.payment_id, deny: res.blocked }); continue; }
        if (res.cancelled) { out.cancelled.push(row.payment_id); continue; }
        out.released.push(row.payment_id);
        await this.#submit(res.row, out);
      }
      return out;
    } finally { this.busy = false; }
  }

  /** Release-time re-check against AUTHORITATIVE state (root replica, freeze, lease, purpose, approver status). */
  #releaseOne(paymentId) {
    return this.store.tx(() => {
      const row = this.store.get(paymentId);
      if (row.state !== 'BUFFERED') return { blocked: ['STATE_CHANGED'] };
      const now = this.now(); const m = this.store.db.prepare('SELECT * FROM cap_evidence WHERE payment_id=?').get(paymentId);
      const deny = [];
      const ctl = this.store.control();
      if (ctl.level !== 'NONE') deny.push(ctl.level === 'FROZEN' ? 'FREEZE_ACTIVE' : 'HOLD_ACTIVE');
      if (this.root.freeze.active) deny.push('ROOT_FREEZE_ACTIVE');
      if (this.root.lockdown.active) deny.push('EMERGENCY_LOCKDOWN_ACTIVE');
      if (this.rootAlarm()) deny.push('ROOT_INTEGRITY_ALARM');
      if (!(this.wallNow() <= this.leaseUntil)) deny.push('WATCHDOG_LEASE_STALE');
      if (now < row.release_at) deny.push('BUFFER_NOT_ELAPSED');
      const cancelWhy = m.epoch !== this.root.epoch ? 'STALE_EPOCH' : m.purpose_version !== this.root.purpose.version ? 'STALE_PURPOSE_VERSION'
        : this.root.creds[m.cred_id]?.status !== 'active' ? 'APPROVER_CREDENTIAL_NOT_ACTIVE' : now >= row.cap_expires_at ? 'CAPABILITY_EXPIRED' : null;
      if (cancelWhy && !deny.some(d => /FREEZE|LOCKDOWN/.test(d))) {
        this.store.move(paymentId, 'BUFFERED', cancelWhy === 'CAPABILITY_EXPIRED' ? 'EXPIRED' : 'CANCELLED', 'policy', { reason: cancelWhy }, { reason: cancelWhy });
        return { cancelled: true };
      }
      if (cancelWhy) deny.push(cancelWhy);
      if (deny.length) return { blocked: deny };
      const keyNonce = (BigInt(this.store.getControl('lastKeyNonce')) + 1n).toString();
      this.store.setControl('lastKeyNonce', keyNonce);
      const signed = this.executor.sign(V2_DOMAINS.LEDGER_TX, { v: LEDGER_TX_VERSION, paymentId: row.payment_id, capId: row.cap_id, intentNonce: row.intent_nonce,
        keyNonce, sender: this.cfg.executorAccount, recipient: row.recipient, asset: row.asset, amountYocto: row.amount, issuedAt: iso(now) });
      const r2 = this.store.move(paymentId, 'BUFFERED', 'RELEASED', 'executor', { keyNonce, finalCheck: 'ALLOW', rootHead: this.root.head, epoch: this.root.epoch },
        { key_nonce: keyNonce, tx_statement: signed.statement, tx_signature: signed.signature, released_at: now });
      return { row: r2 };
    });
  }

  async #submit(row, out, resigned = false) {
    let res;
    try { res = await this.ledger.call('SUBMIT_TX', { tx: { statement: row.tx_statement, signature: row.tx_signature } }); }
    catch (e) {
      const code = e instanceof SafeBoxError ? e.code : 'LEDGER_TRANSPORT';
      this.store.tx(() => {
        const cur = this.store.get(row.payment_id);
        if (code === 'LEDGER_FROZEN') this.store.move(row.payment_id, cur.state, 'FROZEN', 'executor', { ledger: code }, { reason: 'LEDGER_FROZEN' });
        else if (LEDGER_DEFINITIVE.test(code)) this.store.move(row.payment_id, cur.state, 'FAILED', 'executor', { ledger: code }, { reason: code });
        else if (cur.state !== 'UNKNOWN') this.store.move(row.payment_id, cur.state, 'UNKNOWN', 'executor', { ledger: code }, { reason: code });
      });
      (code === 'LEDGER_FROZEN' ? out.blocked : LEDGER_DEFINITIVE.test(code) ? out.failed : out.unknown).push(row.payment_id);
      return;
    }
    this.store.tx(() => {
      const cur = this.store.get(row.payment_id);
      if (res.status === 'SETTLED') { this.store.move(row.payment_id, cur.state, 'SETTLED', 'verifier', { txId: res.txId }, { tx_id: res.txId, ledger_status: 'SETTLED', settled_at: this.now() }); out.settled.push(row.payment_id); }
      else if (res.status === 'VOIDED') this.store.move(row.payment_id, cur.state, 'FAILED', 'verifier', { txId: res.txId }, { tx_id: res.txId, ledger_status: 'VOIDED', reason: 'LEDGER_VOIDED' });
      else this.store.db.prepare('UPDATE payments SET tx_id=?, ledger_status=?, updated_at=? WHERE payment_id=?').run(res.txId, res.status, this.now(), row.payment_id);
    });
  }

  async reconcile(out = { settled: [], blocked: [], failed: [], unknown: [] }) {
    for (const row of this.store.byState(['RELEASED', 'UNKNOWN'])) {
      const txId = row.tx_id ?? digestOf(V2_DOMAINS.LEDGER_TX, row.tx_statement);
      let st; try { st = await this.ledger.call('TX_STATUS', { txId }); } catch { continue; }
      if (st.found && st.status === 'SETTLED') { this.store.tx(() => this.store.move(row.payment_id, row.state, 'SETTLED', 'verifier', { txId }, { tx_id: txId, ledger_status: 'SETTLED', settled_at: this.now() })); out.settled.push(row.payment_id); continue; }
      if (st.found) continue; // pending on ledger
      if (this.store.control().level !== 'NONE' || this.root.freeze.active || this.root.lockdown.active) continue; // never push while frozen
      await this.#submit(row, out); // identical bytes; idempotent on tx id + one-use intent nonce
    }
    return out;
  }

  state() {
    const counts = Object.fromEntries(this.store.db.prepare('SELECT state, COUNT(*) n FROM payments GROUP BY state').all().map(r => [r.state, r.n]));
    return { control: this.store.control(), counts, root: this.C.rootView(this.root), rootAlarm: this.rootAlarm(), leaseFresh: this.wallNow() <= this.leaseUntil, journal: this.store.verifyJournal() };
  }
  evidence() { return this.store.db.prepare('SELECT cap_id, payment_id, cap, approval, cred_id, epoch FROM cap_evidence ORDER BY payment_id').all(); }
  payments() { return this.store.db.prepare('SELECT payment_id, cap_id, recipient, amount, state, proposed_at, release_at, released_at, settled_at, tx_id, reason FROM payments ORDER BY proposed_at, payment_id').all(); }
}

/** IPC op tables. gz = General Zone (untrusted). ctl = supervisor. root = replica feed (Root service -> vault). */
export function vaultOps(v) {
  return {
    gz: {
      PROPOSE: { fields: ['capability', 'approval', 'recipientId', 'amountYocto', 'asset', 'memo'], types: { capability: 'object', approval: 'object' }, maxLen: { memo: 512 },
        handler: (a) => { for (const k of ['capability', 'approval']) if (!a[k] || typeof a[k] !== 'object' || Array.isArray(a[k])) fail('BAD_ARG', k); return v.propose(a); } },
      STATUS: { fields: ['paymentId'], handler: (a) => v.status(a.paymentId) },
      HEALTH: { fields: [], handler: () => ({ ok: true, frozen: v.root.freeze.active, lockdown: v.root.lockdown.active }) },
      ROOT_VIEW: { fields: [], handler: () => v.view() },
    },
    ctl: {
      HEARTBEAT: { fields: [], handler: () => v.heartbeat() },
      HOLD: { fields: ['reason', 'classification'], handler: (a) => v.setLevel('HOLD', a.reason, a.classification) },
      FREEZE: { fields: ['reason', 'classification'], handler: (a) => v.setLevel('FROZEN', a.reason, a.classification) },
      CLEAR_HOLD: { fields: ['reviewRef'], handler: (a) => v.clearHold(a.reviewRef) },
      LIFT_LOCAL_FREEZE: { fields: [], handler: () => v.liftLocalFreeze() },
      TICK: { fields: [], handler: () => v.tick() },
      STATE: { fields: [], handler: () => v.state() },
      PAYMENTS: { fields: [], handler: () => v.payments() },
      EVIDENCE: { fields: [], handler: () => v.evidence() },
      SYNC_ROOT: { fields: ['transitions'], types: { transitions: 'object' }, handler: (a) => v.syncRoot(a.transitions) },
    },
  };
}
export { SensitiveStore };
