// WP3 — Durable capability broker state (SQLite, single node).
// Every lifecycle change is a compare-and-set inside BEGIN IMMEDIATE, plus an
// append-only, hash-chained journal row written in the same transaction.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { fail } from './canonical.mjs';

export const STATES = Object.freeze(['PREPARED', 'AUTHORIZED', 'RESERVED', 'SIGNED', 'SUBMITTED', 'CONFIRMED',
  'FAILED', 'UNKNOWN', 'REJECTED', 'EXPIRED', 'REVOKED']);
export const TERMINAL = Object.freeze(['CONFIRMED', 'FAILED', 'REJECTED', 'EXPIRED', 'REVOKED']);
const ALLOWED = {
  PREPARED: ['AUTHORIZED', 'EXPIRED', 'REVOKED', 'REJECTED'],
  AUTHORIZED: ['RESERVED', 'EXPIRED', 'REVOKED'],
  RESERVED: ['SIGNED', 'FAILED'],
  // -> RESERVED only after chain-state proof that the signed tx can never be included (contract mode).
  SIGNED: ['SUBMITTED', 'UNKNOWN', 'CONFIRMED', 'FAILED', 'RESERVED'],
  SUBMITTED: ['SUBMITTED', 'CONFIRMED', 'FAILED', 'UNKNOWN'],
  UNKNOWN: ['UNKNOWN', 'SUBMITTED', 'CONFIRMED', 'FAILED', 'RESERVED'],
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS mandates (
  mandate_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, statement TEXT NOT NULL, signature TEXT NOT NULL,
  reserved_total TEXT NOT NULL DEFAULT '0', revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS intents (
  intent_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, mandate_id TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE, canonical TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL, challenge TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
  authz TEXT, authz_sig TEXT, proposal_meta TEXT,
  tx_hash TEXT UNIQUE, signed_tx_b64 TEXT, signer_public_key TEXT, signer_nonce TEXT, signed_at TEXT,
  broadcast_count INTEGER NOT NULL DEFAULT 0, outcome TEXT, effect TEXT, released INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS journal (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, intent_id TEXT, from_state TEXT, to_state TEXT, actor TEXT NOT NULL,
  at TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS journal_no_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS journal_no_delete BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
`;

export class SafeBoxStore {
  constructor(path, { now = () => Date.now() } = {}) {
    this.path = path;
    this.now = now;
    this.db = new DatabaseSync(path);
    // busy_timeout first: switching journal mode and creating tables need locks other processes may hold.
    this.db.exec('PRAGMA busy_timeout=10000;');
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;');
    this.db.exec(SCHEMA);
  }
  close() { this.db.close(); }

  #tx(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const r = fn(); this.db.exec('COMMIT'); return r; }
    catch (e) { try { this.db.exec('ROLLBACK'); } catch {} throw e; }
  }
  #iso() { return new Date(this.now()).toISOString(); }

  #journal(intentId, from, to, actor, detail) {
    const prev = this.db.prepare('SELECT entry_hash FROM journal ORDER BY seq DESC LIMIT 1').get();
    const prevHash = prev ? prev.entry_hash : '0'.repeat(64);
    const at = this.#iso();
    const d = JSON.stringify(detail ?? {});
    const entryHash = createHash('sha256').update([prevHash, intentId ?? '', from ?? '', to ?? '', actor, at, d].join('\u0000')).digest('hex');
    this.db.prepare('INSERT INTO journal (intent_id, from_state, to_state, actor, at, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?)')
      .run(intentId ?? null, from ?? null, to ?? null, actor, at, d, prevHash, entryHash);
  }

  // ---- mandates ----
  putMandate({ mandateId, principalId, statement, signature }) {
    return this.#tx(() => {
      if (this.db.prepare('SELECT 1 FROM mandates WHERE mandate_id=?').get(mandateId)) fail('MANDATE_EXISTS');
      this.db.prepare('INSERT INTO mandates (mandate_id, principal_id, statement, signature, created_at) VALUES (?,?,?,?,?)')
        .run(mandateId, principalId, statement, signature, this.#iso());
      this.#journal(null, null, null, 'owner', { event: 'MANDATE_REGISTERED', mandateId, principalId });
    });
  }
  getMandate(mandateId) { return this.db.prepare('SELECT * FROM mandates WHERE mandate_id=?').get(mandateId) ?? null; }
  revokeMandate(mandateId, actor) {
    return this.#tx(() => {
      const r = this.db.prepare('UPDATE mandates SET revoked=1 WHERE mandate_id=?').run(mandateId);
      if (r.changes !== 1) fail('UNKNOWN_MANDATE');
      this.#journal(null, null, null, actor, { event: 'MANDATE_REVOKED', mandateId });
    });
  }

  // ---- intents ----
  insertIntent({ sealed, challenge, proposalMeta }) {
    const i = sealed.intent;
    return this.#tx(() => {
      const t = this.#iso();
      this.db.prepare(`INSERT INTO intents (intent_id, principal_id, mandate_id, digest, canonical, nonce, state, challenge,
        expires_at, proposal_meta, created_at, updated_at) VALUES (?,?,?,?,?,?, 'PREPARED', ?,?,?,?,?)`)
        .run(i.intentId, i.principalId, i.mandateId, sealed.digest, sealed.canonical, i.nonce, challenge, i.expiresAt,
          proposalMeta ?? null, t, t);
      this.#journal(i.intentId, null, 'PREPARED', 'service', { digest: sealed.digest });
    });
  }
  get(intentId) { return this.db.prepare('SELECT * FROM intents WHERE intent_id=?').get(intentId) ?? null; }
  listByState(states) {
    const q = `SELECT * FROM intents WHERE state IN (${states.map(() => '?').join(',')}) ORDER BY created_at`;
    return this.db.prepare(q).all(...states);
  }

  /**
   * Atomic compare-and-set. `guard(row)` runs inside the write transaction and may throw.
   * `patch` columns are written in the same statement as the state change.
   */
  transition(intentId, from, to, { actor = 'service', patch = {}, detail = {}, guard } = {}) {
    if (!STATES.includes(to)) fail('BAD_STATE');
    return this.#tx(() => {
      const row = this.get(intentId);
      if (!row) fail('UNKNOWN_INTENT');
      const froms = Array.isArray(from) ? from : [from];
      if (!froms.includes(row.state)) fail('STATE_CONFLICT', `${row.state} -> ${to}`);
      if (!(ALLOWED[row.state] ?? []).includes(to)) fail('ILLEGAL_TRANSITION', `${row.state} -> ${to}`);
      if (guard) guard(row, this.db);
      const cols = Object.keys(patch);
      for (const c of cols) if (!/^[a-z][a-z0-9_]*$/.test(c)) fail('BAD_COLUMN');
      const sets = ['state=?', 'updated_at=?', ...cols.map(c => `${c}=?`)].join(', ');
      const r = this.db.prepare(`UPDATE intents SET ${sets} WHERE intent_id=? AND state=?`)
        .run(to, this.#iso(), ...cols.map(c => patch[c]), intentId, row.state);
      if (r.changes !== 1) fail('STATE_CONFLICT');
      this.#journal(intentId, row.state, to, actor, detail);
      return this.get(intentId);
    });
  }

  // Mandate accounting inside the RESERVE transaction (called from guard).
  static reserveMandateSpend(db, mandateId, amountYocto, maxTotalYocto) {
    const m = db.prepare('SELECT reserved_total, revoked FROM mandates WHERE mandate_id=?').get(mandateId);
    if (!m) fail('UNKNOWN_MANDATE');
    if (m.revoked) fail('MANDATE_REVOKED');
    const next = BigInt(m.reserved_total) + BigInt(amountYocto);
    if (next > BigInt(maxTotalYocto)) fail('MANDATE_TOTAL_EXCEEDED');
    db.prepare('UPDATE mandates SET reserved_total=? WHERE mandate_id=?').run(next.toString(), mandateId);
  }
  static releaseMandateSpend(db, mandateId, amountYocto) {
    const m = db.prepare('SELECT reserved_total FROM mandates WHERE mandate_id=?').get(mandateId);
    const next = BigInt(m.reserved_total) - BigInt(amountYocto);
    if (next < 0n) fail('MANDATE_ACCOUNTING_ERROR');
    db.prepare('UPDATE mandates SET reserved_total=? WHERE mandate_id=?').run(next.toString(), mandateId);
  }

  /** Highest access-key nonce SafeBox has ever signed with this key (durable local nonce allocator). */
  maxSignerNonce(publicKey) {
    let max = 0n;
    for (const r of this.db.prepare('SELECT signer_nonce FROM intents WHERE signer_public_key=? AND signer_nonce IS NOT NULL').all(publicKey)) {
      const n = BigInt(r.signer_nonce); if (n > max) max = n;
    }
    for (const r of this.db.prepare("SELECT detail FROM journal WHERE to_state='SIGNED'").all()) {
      const d = JSON.parse(r.detail);
      if (d.signerPublicKey === publicKey && d.signerNonce) { const n = BigInt(d.signerNonce); if (n > max) max = n; }
    }
    return max;
  }

  note(intentId, actor, detail) { this.#tx(() => this.#journal(intentId, null, null, actor, detail)); }
  bumpBroadcast(intentId) {
    this.db.prepare('UPDATE intents SET broadcast_count = broadcast_count + 1 WHERE intent_id=?').run(intentId);
  }

  journal(intentId) {
    return intentId ? this.db.prepare('SELECT * FROM journal WHERE intent_id=? ORDER BY seq').all(intentId)
      : this.db.prepare('SELECT * FROM journal ORDER BY seq').all();
  }
  verifyJournalChain() {
    let prev = '0'.repeat(64);
    for (const r of this.journal()) {
      const h = createHash('sha256').update([prev, r.intent_id ?? '', r.from_state ?? '', r.to_state ?? '', r.actor, r.at, r.detail].join('\u0000')).digest('hex');
      if (r.prev_hash !== prev || r.entry_hash !== h) return { ok: false, seq: r.seq };
      prev = h;
    }
    return { ok: true, head: prev };
  }
}
