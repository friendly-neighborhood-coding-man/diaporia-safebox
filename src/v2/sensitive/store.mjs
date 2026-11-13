// Sensitive Zone durable state (SQLite, owned by the Sensitive Zone OS principal only).
// Every lifecycle change is a compare-and-set inside BEGIN IMMEDIATE together with an
// append-only, hash-chained journal row: if the audit row cannot be written, the state change
// does not happen either (fail closed on audit failure).
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { fail } from '../../v1/canonical.mjs';

export const STATES = Object.freeze(['PROPOSED', 'AUTHORIZED', 'RESERVED', 'BUFFERED', 'RELEASED', 'SETTLED',
  'REJECTED', 'FROZEN', 'CANCELLED', 'EXPIRED', 'FAILED', 'UNKNOWN']);
export const TERMINAL = Object.freeze(['SETTLED', 'REJECTED', 'CANCELLED', 'EXPIRED', 'FAILED']);
// States that hold a budget reservation.
export const HOLDING = Object.freeze(['RESERVED', 'BUFFERED', 'RELEASED', 'UNKNOWN', 'FROZEN']);
const ALLOWED = {
  PROPOSED: ['AUTHORIZED', 'REJECTED'],
  AUTHORIZED: ['RESERVED', 'REJECTED'],
  RESERVED: ['BUFFERED'],
  BUFFERED: ['RELEASED', 'FROZEN', 'CANCELLED', 'EXPIRED'],
  RELEASED: ['SETTLED', 'FAILED', 'UNKNOWN', 'FROZEN'],
  UNKNOWN: ['SETTLED', 'FAILED', 'UNKNOWN', 'FROZEN'],
  FROZEN: ['CANCELLED', 'SETTLED'], // SETTLED only if the ledger proves the transfer already happened
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS control (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policies (policy_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, statement TEXT NOT NULL,
  signature TEXT NOT NULL, digest TEXT NOT NULL, loaded_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS caps_used (cap_id TEXT PRIMARY KEY, payment_id TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS caps_revoked (cap_id TEXT PRIMARY KEY, at INTEGER NOT NULL, statement TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS payments (payment_id TEXT PRIMARY KEY, cap_id TEXT NOT NULL, cap_digest TEXT NOT NULL,
  principal_id TEXT NOT NULL, policy_id TEXT NOT NULL, policy_digest TEXT NOT NULL, recipient TEXT NOT NULL,
  asset TEXT NOT NULL, amount TEXT NOT NULL, intent_nonce TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
  proposed_at INTEGER NOT NULL, release_at INTEGER, cap_expires_at INTEGER NOT NULL, released_at INTEGER, settled_at INTEGER,
  key_nonce TEXT UNIQUE, tx_statement TEXT, tx_signature TEXT, tx_id TEXT UNIQUE, ledger_status TEXT,
  reason TEXT, memo TEXT, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, channel TEXT NOT NULL,
  op TEXT, outcome TEXT NOT NULL, codes TEXT NOT NULL, cap_id TEXT, payment_id TEXT);
CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, payment_id TEXT, from_state TEXT, to_state TEXT,
  actor TEXT NOT NULL, at INTEGER NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS journal_no_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS journal_no_delete BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS settled_is_final BEFORE UPDATE ON payments WHEN OLD.state='SETTLED' BEGIN SELECT RAISE(ABORT, 'settled is final'); END;
`;

export class SensitiveStore {
  constructor(path, { now, auditFault = null } = {}) {
    this.path = path; this.now = now; this.auditFault = auditFault; // auditFault: test hook () => boolean
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    this.db.exec(SCHEMA);
    if (!this.getControl('level')) this.tx(() => { this.setControl('level', 'NONE'); this.setControl('lastKeyNonce', '0'); this.journal(null, null, null, 'system', { event: 'INIT' }); });
  }
  close() { this.db.close(); }
  tx(fn) { this.db.exec('BEGIN IMMEDIATE'); try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { try { this.db.exec('ROLLBACK'); } catch {} throw e; } }
  getControl(k) { return this.db.prepare('SELECT v FROM control WHERE k=?').get(k)?.v ?? null; }
  setControl(k, v) { this.db.prepare('INSERT INTO control (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v)); }
  control() { return { level: this.getControl('level'), reason: this.getControl('reason'), since: this.getControl('since'), classification: this.getControl('classification') }; }

  journal(paymentId, from, to, actor, detail) {
    if (this.auditFault?.()) fail('AUDIT_UNAVAILABLE');
    const prev = this.db.prepare('SELECT entry_hash FROM journal ORDER BY seq DESC LIMIT 1').get()?.entry_hash ?? '0'.repeat(64);
    const at = this.now(); const d = JSON.stringify(detail ?? {});
    const h = createHash('sha256').update([prev, paymentId ?? '', from ?? '', to ?? '', actor, at, d].join('\u0000')).digest('hex');
    this.db.prepare('INSERT INTO journal (payment_id, from_state, to_state, actor, at, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?)')
      .run(paymentId, from, to, actor, at, d, prev, h);
  }
  decision(channel, op, outcome, codes, capId = null, paymentId = null) {
    try { this.db.prepare('INSERT INTO decisions (at, channel, op, outcome, codes, cap_id, payment_id) VALUES (?,?,?,?,?,?,?)')
      .run(this.now(), channel, op, outcome, JSON.stringify(codes).slice(0, 1000), capId, paymentId); } catch { /* decision log is best-effort; journal is authoritative */ }
  }

  get(paymentId) { return this.db.prepare('SELECT * FROM payments WHERE payment_id=?').get(paymentId) ?? null; }
  byState(states) { return this.db.prepare(`SELECT * FROM payments WHERE state IN (${states.map(() => '?').join(',')}) ORDER BY proposed_at, payment_id`).all(...states); }

  /** Compare-and-set state change (must be called inside tx()). */
  move(paymentId, from, to, actor, detail = {}, patch = {}) {
    const row = this.get(paymentId);
    if (!row) fail('UNKNOWN_PAYMENT');
    const froms = Array.isArray(from) ? from : [from];
    if (!froms.includes(row.state)) fail('STATE_CONFLICT', `${row.state}->${to}`);
    if (!(ALLOWED[row.state] ?? []).includes(to)) fail('ILLEGAL_TRANSITION', `${row.state}->${to}`);
    const cols = Object.keys(patch);
    for (const c of cols) if (!/^[a-z][a-z0-9_]*$/.test(c)) fail('BAD_COLUMN');
    const sets = ['state=?', 'updated_at=?', ...cols.map(c => `${c}=?`)].join(', ');
    const r = this.db.prepare(`UPDATE payments SET ${sets} WHERE payment_id=? AND state=?`).run(to, this.now(), ...cols.map(c => patch[c]), paymentId, row.state);
    if (r.changes !== 1) fail('STATE_CONFLICT');
    this.journal(paymentId, row.state, to, actor, detail);
    return this.get(paymentId);
  }

  usage(principalId) {
    let committed = 0n, pendingCount = 0, pendingExposure = 0n, executions = 0;
    for (const r of this.db.prepare('SELECT state, amount FROM payments WHERE principal_id=?').all(principalId)) {
      const a = BigInt(r.amount);
      if (HOLDING.includes(r.state) || r.state === 'SETTLED') committed += a;
      if (HOLDING.includes(r.state)) { pendingCount++; pendingExposure += a; }
      if (['RELEASED', 'UNKNOWN', 'SETTLED'].includes(r.state)) executions++;
    }
    // RELEASED/UNKNOWN count both as pending exposure and as executions (already signed).
    const inflight = this.db.prepare("SELECT COUNT(*) n FROM payments WHERE principal_id=? AND state IN ('RELEASED','UNKNOWN')").get(principalId).n;
    return { committedYocto: committed.toString(), pendingCount: pendingCount - inflight, pendingExposureYocto: pendingExposure.toString(), executions };
  }

  journalRows(sinceSeq = 0) { return this.db.prepare('SELECT * FROM journal WHERE seq>? ORDER BY seq').all(sinceSeq); }
  verifyJournal() {
    let prev = '0'.repeat(64);
    for (const r of this.db.prepare('SELECT * FROM journal ORDER BY seq').all()) {
      const h = createHash('sha256').update([prev, r.payment_id ?? '', r.from_state ?? '', r.to_state ?? '', r.actor, r.at, r.detail].join('\u0000')).digest('hex');
      if (r.prev_hash !== prev || r.entry_hash !== h) return { ok: false, seq: r.seq };
      prev = h;
    }
    return { ok: true, head: prev };
  }
}
