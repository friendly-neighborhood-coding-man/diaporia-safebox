// Purpose Root service: the SEQUENCER of the root chain. It stamps time and order, verifies every transition with the
// same pure function every other domain uses, and persists the chain append-only. It holds NO owner key and has no
// operation that edits state directly: the only write is "append a transition that verifies".
// Its admin port is the secure injection port for owner devices (strict schema, canonical encoding, per-action
// authorization). There is no op for arbitrary signing, secret export, recovery completion by fiat, or financial release.
import { DatabaseSync } from 'node:sqlite';
import { fail, exactFields, iso, canon } from '../common/canon.mjs';
import { genesisState, applyTransition, rootView, TR_V } from './chain.mjs';
import { isPlainObject } from '../../v1/canonical.mjs';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS chain (seq INTEGER PRIMARY KEY, tr TEXT NOT NULL, head TEXT NOT NULL, type TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rejects (n INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, type TEXT, code TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS chain_no_update BEFORE UPDATE ON chain BEGIN SELECT RAISE(ABORT, 'root chain is append-only'); END;
CREATE TRIGGER IF NOT EXISTS chain_no_delete BEFORE DELETE ON chain BEGIN SELECT RAISE(ABORT, 'root chain is append-only'); END;
`;

export class RootService {
  constructor({ genesis, pinnedChainId, dbPath = ':memory:', now, onEffects = null, crashAfterPersist = null }) {
    this.genesis = genesis; this.pinnedChainId = pinnedChainId; this.now = now; this.onEffects = onEffects; this.crashAfterPersist = crashAfterPersist;
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    this.db.exec(SCHEMA);
    this.#rebuild();
  }
  #rebuild() {
    let st = genesisState(this.genesis, { pinnedChainId: this.pinnedChainId });
    for (const r of this.db.prepare('SELECT * FROM chain ORDER BY seq').all()) { st = applyTransition(st, JSON.parse(r.tr)).state; if (st.head !== r.head) fail('ROOT_STORE_CORRUPT'); }
    this.state = st;
  }
  close() { this.db.close(); }
  /** Strict-schema submission from an owner device / recovery service / supervisor. Root assigns seq, prev and time. */
  submit(req) {
    exactFields(req, ['action'], ['approvals', 'guardianApprovals', 'attestation'], 'SUBMIT_FIELDS');
    if (!isPlainObject(req.action)) fail('SUBMIT_ACTION');
    if (Buffer.byteLength(JSON.stringify(req)) > 192 * 1024) fail('SUBMIT_TOO_LARGE');
    const at = Math.max(this.now(), this.state.lastAt);
    const tr = { v: TR_V, seq: String(this.state.seq + 1), prev: this.state.head, at: iso(at), action: req.action };
    for (const k of ['approvals', 'guardianApprovals', 'attestation']) if (k in req) tr[k] = req[k];
    canon(tr); // canonical encodability = data, never code
    let r;
    try { r = applyTransition(this.state, tr); }
    catch (e) { try { this.db.prepare('INSERT INTO rejects (at, type, code) VALUES (?,?,?)').run(at, String(req.action.type ?? '').slice(0, 40), e.code ?? 'ERROR'); } catch {} throw e; }
    // compare-and-append: a concurrent writer that got there first makes this a fork and the insert fails
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const top = this.db.prepare('SELECT MAX(seq) m FROM chain').get().m ?? 0;
      if (top !== this.state.seq) fail('ROOT_CONCURRENT_APPEND');
      this.db.prepare('INSERT INTO chain (seq, tr, head, type, at) VALUES (?,?,?,?,?)').run(Number(tr.seq), JSON.stringify(tr), r.state.head, req.action.type, at);
      this.db.exec('COMMIT');
    } catch (e) { try { this.db.exec('ROLLBACK'); } catch {} throw e; }
    this.crashAfterPersist?.(tr);
    this.state = r.state;
    this.onEffects?.(r.effects, tr);
    return { seq: tr.seq, head: r.state.head, effects: r.effects };
  }
  chain(sinceSeq = 0) { return this.db.prepare('SELECT tr FROM chain WHERE seq > ? ORDER BY seq').all(Number(sinceSeq) || 0).map(r => JSON.parse(r.tr)); }
  view() { return { ...rootView(this.state), now: this.now() }; }
  rejects() { return this.db.prepare('SELECT * FROM rejects ORDER BY n').all(); }
}

export function rootOps(root) {
  return {
    // owner devices (secure injection port) — the General Zone has no access to this socket
    admin: {
      SUBMIT: { fields: ['request'], types: { request: 'object' }, handler: (a) => root.submit(a.request) },
      VIEW: { fields: [], handler: () => root.view() },
    },
    // replica feed (vault, recovery service, supervisor): read-only
    replica: {
      CHAIN: { fields: ['sinceSeq'], handler: (a) => root.chain(a.sinceSeq) },
      VIEW: { fields: [], handler: () => root.view() },
      GENESIS: { fields: [], handler: () => root.genesis },
    },
    // recovery service: may append recovery-protocol transitions only (they still need owner/guardian/IDV evidence)
    recovery: {
      SUBMIT_RECOVERY: { fields: ['request'], types: { request: 'object' }, handler: (a) => {
        if (!/^RECOVERY_(DISPATCH|COMPLETE)$|^RECONSTITUTE$/.test(a.request?.action?.type ?? '')) fail('OP_SCOPE', 'recovery port');
        return root.submit(a.request); } },
      CHAIN: { fields: ['sinceSeq'], handler: (a) => root.chain(a.sinceSeq) },
    },
  };
}
