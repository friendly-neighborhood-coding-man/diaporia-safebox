// Mock NEAR Ledger (V2). Synthetic accounts and balances only; never touches a real network.
// Plays the role of the chain: it accepts only transfers signed by the pinned executor key,
// enforces strictly increasing key nonces, one-use intent nonces, a per-transfer cap,
// a freeze flag, and (optionally) delayed settlement. Settled transfers are irreversible.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { fail, requireExactFields, atomicAmount, isoMillis, hex, parseCanonical, SafeBoxError } from '../../v1/canonical.mjs';
import { V2_DOMAINS, verifySig, digestOf } from '../common/crypto.mjs';

export const LEDGER_TX_VERSION = 'safebox.v2.ledgertx';
const TX_FIELDS = ['v', 'paymentId', 'capId', 'intentNonce', 'keyNonce', 'sender', 'recipient', 'asset', 'amountYocto', 'issuedAt'];
export const MOCK_ACCOUNT_RE = /^[a-z0-9][a-z0-9-]{1,40}\.mock$/;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, balance TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS txs (seq INTEGER PRIMARY KEY AUTOINCREMENT, tx_id TEXT NOT NULL UNIQUE,
  payment_id TEXT NOT NULL UNIQUE, intent_nonce TEXT NOT NULL UNIQUE, key_nonce TEXT NOT NULL,
  sender TEXT NOT NULL, recipient TEXT NOT NULL, amount TEXT NOT NULL, status TEXT NOT NULL,
  submitted_at INTEGER NOT NULL, settle_at INTEGER NOT NULL, settled_at INTEGER, statement TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejects (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, code TEXT NOT NULL, tx_id TEXT);
CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, event TEXT NOT NULL,
  detail TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS txs_no_delete BEFORE DELETE ON txs BEGIN SELECT RAISE(ABORT, 'ledger txs are irreversible'); END;
CREATE TRIGGER IF NOT EXISTS j_no_update BEFORE UPDATE ON journal BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS j_no_delete BEFORE DELETE ON journal BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS settled_final BEFORE UPDATE ON txs WHEN OLD.status='SETTLED' BEGIN SELECT RAISE(ABORT, 'settled is final'); END;
`;

export class MockLedger {
  constructor(path, { now }) {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    this.db.exec(SCHEMA);
    this.now = now;
  }
  close() { this.db.close(); }
  #tx(fn) { this.db.exec('BEGIN IMMEDIATE'); try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { try { this.db.exec('ROLLBACK'); } catch {} throw e; } }
  #meta(k) { return this.db.prepare('SELECT v FROM meta WHERE k=?').get(k)?.v ?? null; }
  #setMeta(k, v) { this.db.prepare('INSERT INTO meta (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, String(v)); }
  #journal(event, detail) {
    const prev = this.db.prepare('SELECT entry_hash FROM journal ORDER BY seq DESC LIMIT 1').get()?.entry_hash ?? '0'.repeat(64);
    const at = this.now(); const d = JSON.stringify(detail ?? {});
    const h = createHash('sha256').update([prev, at, event, d].join('\u0000')).digest('hex');
    this.db.prepare('INSERT INTO journal (at, event, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?)').run(at, event, d, prev, h);
  }

  /** One-time genesis (trusted launcher config). Pins executor + owner keys. */
  genesis({ executorAccount, executorKey, ownerKey, accounts, maxPaymentYocto, settleDelayMs = 0 }) {
    return this.#tx(() => {
      if (this.#meta('genesis')) return false;
      if (!MOCK_ACCOUNT_RE.test(executorAccount)) fail('BAD_ACCOUNT');
      for (const [id, bal] of Object.entries(accounts)) {
        if (!MOCK_ACCOUNT_RE.test(id)) fail('BAD_ACCOUNT', id);
        this.db.prepare('INSERT INTO accounts (id, balance) VALUES (?,?)').run(id, atomicAmount(bal, 'balance', { allowZero: true }));
      }
      if (!this.db.prepare('SELECT 1 FROM accounts WHERE id=?').get(executorAccount)) fail('EXECUTOR_ACCOUNT_MISSING');
      for (const [k, v] of Object.entries({ executorAccount, executorKey, ownerKey, maxPaymentYocto: atomicAmount(maxPaymentYocto), settleDelayMs, lastKeyNonce: '0', frozen: '0', genesis: '1' })) this.#setMeta(k, v);
      this.#journal('GENESIS', { executorAccount, executorKey, ownerKey, accounts, maxPaymentYocto, settleDelayMs });
      return true;
    });
  }

  #reject(code, txId = null) {
    this.#tx(() => { this.db.prepare('INSERT INTO rejects (at, code, tx_id) VALUES (?,?,?)').run(this.now(), code, txId); });
    fail(code);
  }

  /** Submit an executor-signed transfer. Idempotent on tx id: re-submitting identical bytes never pays twice. */
  submit({ statement, signature }) {
    if (typeof statement !== 'string' || statement.length > 2048) this.#reject('LEDGER_BAD_TX');
    let tx;
    try { tx = parseCanonical(statement, 2048); requireExactFields(tx, TX_FIELDS); } catch { this.#reject('LEDGER_BAD_TX'); }
    const txId = digestOf(V2_DOMAINS.LEDGER_TX, statement);
    if (!verifySig(V2_DOMAINS.LEDGER_TX, statement, signature, this.#meta('executorKey'))) this.#reject('LEDGER_BAD_SIGNATURE', txId);
    const existing = this.db.prepare('SELECT tx_id, status FROM txs WHERE tx_id=?').get(txId);
    if (existing) { this.settleDue(); return { txId, status: this.txStatus(txId).status, duplicate: true }; }
    try {
      if (tx.v !== LEDGER_TX_VERSION) fail('LEDGER_BAD_TX');
      hex(tx.intentNonce, 16, 'intentNonce'); isoMillis(tx.issuedAt, 'issuedAt');
      if (!/^[1-9][0-9]{0,15}$/.test(tx.keyNonce)) fail('LEDGER_BAD_TX');
      if (!/^[a-z0-9][a-z0-9_-]{2,63}$/.test(tx.paymentId)) fail('LEDGER_BAD_TX');
      if (typeof tx.capId !== 'string' || !/^[0-9a-f-]{36}$/.test(tx.capId)) fail('LEDGER_BAD_TX');
      if (tx.asset !== 'NEAR') fail('LEDGER_UNSUPPORTED_ASSET');
      atomicAmount(tx.amountYocto);
    } catch (e) { this.#reject(e.code === 'LEDGER_UNSUPPORTED_ASSET' ? e.code : 'LEDGER_BAD_TX', txId); }
    let result;
    try {
      result = this.#tx(() => {
        if (this.#meta('frozen') === '1') fail('LEDGER_FROZEN');
        if (tx.sender !== this.#meta('executorAccount')) fail('LEDGER_WRONG_SENDER');
        if (this.db.prepare('SELECT 1 FROM txs WHERE intent_nonce=?').get(tx.intentNonce)) fail('LEDGER_INTENT_NONCE_USED');
        if (this.db.prepare('SELECT 1 FROM txs WHERE payment_id=?').get(tx.paymentId)) fail('LEDGER_PAYMENT_ID_USED');
        if (BigInt(tx.keyNonce) <= BigInt(this.#meta('lastKeyNonce'))) fail('LEDGER_KEY_NONCE_STALE');
        if (BigInt(tx.amountYocto) > BigInt(this.#meta('maxPaymentYocto'))) fail('LEDGER_AMOUNT_OVER_CAP');
        const to = this.db.prepare('SELECT balance FROM accounts WHERE id=?').get(tx.recipient);
        if (!to) fail('LEDGER_UNKNOWN_RECIPIENT');
        if (tx.recipient === tx.sender) fail('LEDGER_SELF_TRANSFER');
        const from = this.db.prepare('SELECT balance FROM accounts WHERE id=?').get(tx.sender);
        if (BigInt(from.balance) < BigInt(tx.amountYocto)) fail('LEDGER_INSUFFICIENT_FUNDS');
        const now = this.now(), settleAt = now + Number(this.#meta('settleDelayMs'));
        this.db.prepare('UPDATE accounts SET balance=? WHERE id=?').run((BigInt(from.balance) - BigInt(tx.amountYocto)).toString(), tx.sender);
        this.#setMeta('lastKeyNonce', tx.keyNonce);
        this.db.prepare(`INSERT INTO txs (tx_id, payment_id, intent_nonce, key_nonce, sender, recipient, amount, status, submitted_at, settle_at, statement, signature)
          VALUES (?,?,?,?,?,?,?, 'PENDING', ?,?,?,?)`).run(txId, tx.paymentId, tx.intentNonce, tx.keyNonce, tx.sender, tx.recipient, tx.amountYocto, now, settleAt, statement, signature);
        this.#journal('TX_ACCEPTED', { txId, paymentId: tx.paymentId, capId: tx.capId, recipient: tx.recipient, amount: tx.amountYocto, settleAt });
        return { txId };
      });
    } catch (e) { if (e instanceof SafeBoxError) this.#reject(e.code, txId); throw e; }
    this.settleDue();
    return { txId: result.txId, status: this.txStatus(result.txId).status, duplicate: false };
  }

  /** Settles due PENDING transfers unless frozen. Credit happens only here. */
  settleDue() {
    if (this.#meta('frozen') === '1') return 0;
    const now = this.now(); let n = 0;
    for (const t of this.db.prepare("SELECT * FROM txs WHERE status='PENDING' AND settle_at<=? ORDER BY seq").all(now)) {
      this.#tx(() => {
        const cur = this.db.prepare('SELECT status FROM txs WHERE tx_id=?').get(t.tx_id);
        if (cur.status !== 'PENDING' || this.#meta('frozen') === '1') return;
        const to = this.db.prepare('SELECT balance FROM accounts WHERE id=?').get(t.recipient);
        this.db.prepare('UPDATE accounts SET balance=? WHERE id=?').run((BigInt(to.balance) + BigInt(t.amount)).toString(), t.recipient);
        this.db.prepare("UPDATE txs SET status='SETTLED', settled_at=? WHERE tx_id=?").run(now, t.tx_id);
        this.#journal('TX_SETTLED', { txId: t.tx_id });
        n++;
      });
    }
    return n;
  }

  freeze(reason) {
    return this.#tx(() => {
      if (this.#meta('frozen') !== '1') { this.#setMeta('frozen', '1'); this.#setMeta('frozenAt', this.now()); this.#setMeta('frozenReason', String(reason).slice(0, 200)); this.#journal('FROZEN', { reason }); }
      return this.state();
    });
  }
  unfreeze({ statement, signature }) {
    if (!verifySig(V2_DOMAINS.UNFREEZE, statement, signature, this.#meta('ownerKey'))) fail('LEDGER_BAD_UNFREEZE');
    const u = parseCanonical(statement, 1024);
    if (u.target !== 'mock-ledger' || u.frozenAt !== String(this.#meta('frozenAt'))) fail('LEDGER_BAD_UNFREEZE');
    return this.#tx(() => { this.#setMeta('frozen', '0'); this.#journal('UNFROZEN', { statement }); return this.state(); });
  }
  state() { return { frozen: this.#meta('frozen') === '1', frozenAt: this.#meta('frozenAt'), frozenReason: this.#meta('frozenReason'), lastKeyNonce: this.#meta('lastKeyNonce'), executorAccount: this.#meta('executorAccount'), maxPaymentYocto: this.#meta('maxPaymentYocto') }; }

  txStatus(txId) {
    const t = this.db.prepare('SELECT tx_id, payment_id, status, recipient, amount, submitted_at, settled_at FROM txs WHERE tx_id=?').get(txId);
    return t ? { found: true, txId: t.tx_id, paymentId: t.payment_id, status: t.status, recipient: t.recipient, amountYocto: t.amount, submittedAt: t.submitted_at, settledAt: t.settled_at } : { found: false, txId, status: 'NOT_FOUND' };
  }
  transfers(sinceSeq = 0) {
    return this.db.prepare('SELECT seq, tx_id, payment_id, intent_nonce, key_nonce, sender, recipient, amount, status, submitted_at, settle_at, settled_at, statement, signature FROM txs WHERE seq>? ORDER BY seq').all(sinceSeq);
  }
  balances() { return Object.fromEntries(this.db.prepare('SELECT id, balance FROM accounts ORDER BY id').all().map(r => [r.id, r.balance])); }
  rejects() { return this.db.prepare('SELECT * FROM rejects ORDER BY seq').all(); }
  verifyJournal() {
    let prev = '0'.repeat(64);
    for (const r of this.db.prepare('SELECT * FROM journal ORDER BY seq').all()) {
      const h = createHash('sha256').update([prev, r.at, r.event, r.detail].join('\u0000')).digest('hex');
      if (r.prev_hash !== prev || r.entry_hash !== h) return { ok: false, seq: r.seq };
      prev = h;
    }
    return { ok: true, head: prev };
  }
}

/** IPC op tables. exec: Sensitive Zone executor only. read: supervisor verifier. admin: supervisor only. */
export function ledgerOps(ledger) {
  const exec = {
    SUBMIT_TX: { fields: ['tx'], types: { tx: 'signed' }, handler: (a) => ledger.submit(a.tx) },
    TX_STATUS: { fields: ['txId'], handler: (a) => { ledger.settleDue(); return ledger.txStatus(String(a.txId).slice(0, 64)); } },
  };
  const read = {
    TRANSFERS: { fields: ['sinceSeq'], handler: (a) => { ledger.settleDue(); return ledger.transfers(Number(a.sinceSeq) || 0); } },
    BALANCES: { fields: [], handler: () => { ledger.settleDue(); return ledger.balances(); } },
    TX_STATUS: exec.TX_STATUS,
    STATE: { fields: [], handler: () => ({ ...ledger.state(), journal: ledger.verifyJournal() }) },
    REJECTS: { fields: [], handler: () => ledger.rejects() },
  };
  const admin = {
    FREEZE: { fields: ['reason'], handler: (a) => ledger.freeze(a.reason) },
    UNFREEZE: { fields: ['unfreeze'], types: { unfreeze: 'signed' }, handler: (a) => ledger.unfreeze(a.unfreeze) },
    SETTLE_DUE: { fields: [], handler: () => ({ settled: ledger.settleDue() }) },
  };
  return { exec, read, admin };
}
