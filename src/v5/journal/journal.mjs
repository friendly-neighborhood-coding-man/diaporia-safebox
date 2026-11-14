// V5 Immutable Action Footprint Journal (tamper-EVIDENT, not tamper-proof).
// * Append-only SQLite table, every event hash-linked to the previous one: hash = SHA-256(domain || canonical(event)).
// * Independently signed checkpoints (journal checkpoint key) pushed to independent witness replicas; deletion,
//   truncation, reordering or modification is DETECTED by comparing the chain against witness checkpoints. An
//   infrastructure administrator CAN delete the local file; that is detectable, not impossible.
// * Producers receive a layer-bound writer capability (ROOT, VAULT, CONTRACT, NOTIFY, RISK, ANALYSIS): a component cannot
//   write events as another layer. The Analyst's writer can only append ANALYSIS findings that reference events; it can
//   never modify or delete an underlying event.
// * Privacy: forbidden fields (keys, secrets, PINs, biometrics, raw challenge responses / assertions) are rejected at
//   append time. Principal references are keyed pseudonyms. Sensitive metadata is sealed with AES-256-GCM under a
//   per-period key (deleting a period key crypto-shreds that period while the hash chain still verifies).
// * Flood control: rejected-attempt events are recorded only after trust-boundary validation, and at most N per
//   principal per hour; the excess is counted and summarized in one ATTEMPTS_SUPPRESSED event.
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { fail, iso, canon } from '../../v3/common/canon.mjs';
import { V5_DOMAINS, d5hex, newSigner5, verifyObj5, pseudonymizer, seal, unseal } from '../common/v5.mjs';

export const LAYERS = Object.freeze(['ROOT', 'VAULT', 'CONTRACT', 'NOTIFY', 'RISK', 'ANALYSIS', 'REPORT']);
export const EVENT_V = 'safebox.v5.journal-event';
/**
 * V6 hardening P1.7 (issue #14): security-critical events are checkpointed to the witnesses the moment they are written,
 * so deleting one from the local file (tail truncation) is always detected. Only non-critical events written after the
 * newest checkpoint (at most checkpointEvery - 1) can still vanish undetected. Rejected attempts and notification
 * retries are deliberately NOT in this set: an attacker must not be able to force a witness write per request.
 * PAYMENT_PROPOSED is not in it either (V5 baseline checkpoint counts are kept): an owner payment is covered by its
 * OWNER_PAYMENT_APPROVAL_VERIFIED event; a delegated payment's PAYMENT_PROPOSED in the tail is the remaining gap.
 */
export const CHECKPOINT_NOW_TYPES = new Set(['OWNER_PAYMENT_APPROVAL_VERIFIED', 'PAYMENT_ACCELERATED_RAPID_USE', 'FROZEN', 'UNFROZEN',
  'HOLD_CREATED', 'HOLD_CONFIRMED', 'HOLD_RELEASED', 'HOLD_ESCALATED', 'HOLD_EXPIRED', 'HOLDS_RELEASED_BY_UNSUSPEND', 'REVOKED', 'SUSPENDED', 'UNSUSPENDED',
  'INCIDENT_OPENED', 'INCIDENT_ESCALATED', 'DELEGATION_GRANTED', 'DELEGATION_REVOKED', 'RAPID_USE_ACTIVATED', 'RAPID_USE_REVOKED', 'CONTEST_RESOLVED', 'ROOT_REJECTED']);
const ZERO = '0'.repeat(64);
const FORBIDDEN_KEY = /^(private_?key|privatekey|secret|recovery_?secret|seed|pin|passcode|password|biometric\w*|fingerprint|face_?data|webauthn|assertion|signature|sig|challenge_?response|mnemonic|api_?key|auth_?token|otp)$/i;
const FORBIDDEN_VALUE = /(-----BEGIN|PRIVATE KEY|"authenticatorData"|clientDataJSON)/;
export const RETENTION_POLICY = Object.freeze({
  hashChain: 'retained for the life of the account plus 7 years (no personal data in the chain itself)',
  sealedMetadata: 'sealed per calendar month; key destroyed after 400 days (crypto-shredding); auditor role may unseal before that',
  notificationAddresses: 'only in the notification service address book (encrypted at rest); never in the journal',
  analystFindings: 'retained with the chain; marked INFERRED unless independently corroborated',
});
export const ACCESS_POLICY = Object.freeze({
  analyst: 'pseudonymous view, no sealed metadata, untrusted text wrapped as data',
  auditor: 'pseudonymous view + sealed metadata of periods whose key still exists',
  owner: 'own account, de-pseudonymized principal references, sealed metadata',
  verifier: 'hashes, checkpoints and event types only',
});

function assertPrivacy(o, path = '') {
  if (o === null || o === undefined) return;
  if (typeof o === 'string') { if (FORBIDDEN_VALUE.test(o)) fail('JOURNAL_PRIVACY_VIOLATION', path); return; }
  if (Array.isArray(o)) { o.forEach((x, i) => assertPrivacy(x, `${path}[${i}]`)); return; }
  if (typeof o === 'object') for (const [k, v] of Object.entries(o)) { if (FORBIDDEN_KEY.test(k)) fail('JOURNAL_PRIVACY_VIOLATION', path + '.' + k); assertPrivacy(v, path + '.' + k); }
}
const strify = (o) => JSON.parse(JSON.stringify(o, (k, v) => typeof v === 'number' || typeof v === 'boolean' ? String(v) : v === null ? '-' : v));
const ascii = (v) => String(v).replace(/[^\x20-\x7e]/g, '?').slice(0, 400);
function asciiDeep(o) { if (typeof o === 'string') return ascii(o); if (Array.isArray(o)) return o.slice(0, 64).map(asciiDeep); if (o && typeof o === 'object') return Object.fromEntries(Object.entries(o).slice(0, 48).map(([k, v]) => [k.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 63) || 'k', asciiDeep(v)])); return ascii(o); }

export class Witness {
  constructor(path = ':memory:', publicKey) {
    this.db = new DatabaseSync(path); this.publicKey = publicKey;
    this.db.exec('CREATE TABLE IF NOT EXISTS checkpoints (n INTEGER PRIMARY KEY, seq INTEGER NOT NULL, head TEXT NOT NULL, statement TEXT NOT NULL, sig TEXT NOT NULL)');
  }
  /** A witness accepts only correctly signed, monotonically extending checkpoints. */
  accept(cp) {
    if (!verifyObj5(V5_DOMAINS.JOURNAL_CHECKPOINT, cp.statement, cp.sig, this.publicKey)) fail('WITNESS_BAD_SIGNATURE');
    const last = this.db.prepare('SELECT * FROM checkpoints ORDER BY n DESC LIMIT 1').get();
    if (last && Number(cp.statement.seq) <= last.seq) fail('WITNESS_NON_MONOTONIC');
    this.db.prepare('INSERT INTO checkpoints (seq, head, statement, sig) VALUES (?,?,?,?)').run(Number(cp.statement.seq), cp.statement.head, JSON.stringify(cp.statement), cp.sig);
  }
  all() { return this.db.prepare('SELECT * FROM checkpoints ORDER BY n').all().map(r => ({ statement: JSON.parse(r.statement), sig: r.sig })); }
}

export class FootprintJournal {
  constructor({ path = ':memory:', now, accountId, checkpointEvery = 25, perPrincipalAttemptsPerHour = 20, witnesses = null, signer = null }) {
    this.db = new DatabaseSync(path); this.now = now; this.accountId = accountId; this.checkpointEvery = checkpointEvery; this.attemptCap = perPrincipalAttemptsPerHour;
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
    this.db.exec(`CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, layer TEXT NOT NULL, type TEXT NOT NULL, at INTEGER NOT NULL,
        body TEXT NOT NULL, sealed TEXT, period TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
      CREATE TRIGGER IF NOT EXISTS ev_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS ev_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
      CREATE TABLE IF NOT EXISTS suppressed (k TEXT PRIMARY KEY, n INTEGER NOT NULL);`);
    this.signer = signer ?? newSigner5('journal-checkpoint');
    this.witnesses = witnesses ?? [new Witness(':memory:', this.signer.publicKey), new Witness(':memory:', this.signer.publicKey)];
    this.pseudo = pseudonymizer(randomBytes(32)); this.reverse = new Map();
    this.periodKeys = new Map(); this.attempts = new Map();
    this.stats = { appended: 0, suppressed: 0, rejectedPrivacy: 0, checkpoints: 0, bytes: 0 };
  }
  ref(kind, value) { const p = this.pseudo(kind, value); this.reverse.set(p, `${kind}:${value}`); return p; }
  #periodKey(period) { if (!this.periodKeys.has(period)) this.periodKeys.set(period, randomBytes(32)); return this.periodKeys.get(period); }
  /** Retention: destroy a period key -> that period's sealed metadata becomes unreadable; the hash chain still verifies. */
  shred(period) { this.periodKeys.set(period, null); }

  /** Layer-bound writer capability. */
  writer(layer) {
    if (!LAYERS.includes(layer)) fail('JOURNAL_LAYER');
    const j = this;
    return Object.freeze({ layer, append: (ev) => j.#append(layer, ev), attempt: (ev) => j.#attempt(layer, ev) });
  }
  /** Rejected attempts: recorded only after validation, and rate-limited per principal. */
  #attempt(layer, ev) {
    const hour = Math.floor(this.now() / 3600_000); const k = `${layer}|${ev.principal ?? '-'}|${hour}`;
    const n = (this.attempts.get(k) ?? 0) + 1; this.attempts.set(k, n);
    if (n > this.attemptCap) {
      this.stats.suppressed++;
      this.db.prepare('INSERT INTO suppressed (k, n) VALUES (?, 1) ON CONFLICT(k) DO UPDATE SET n=n+1').run(k);
      if (n === this.attemptCap + 1) return this.#append(layer, { type: 'ATTEMPTS_SUPPRESSED', principal: ev.principal, outcome: 'RATE_LIMITED', data: { window: String(hour), cap: String(this.attemptCap) } });
      return null;
    }
    return this.#append(layer, ev);
  }
  #append(layer, ev) {
    try { assertPrivacy(ev); } catch (e) { this.stats.rejectedPrivacy++; throw e; }
    const at = this.now(); const period = iso(at).slice(0, 7);
    const prev = this.db.prepare('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get();
    const seq = (prev?.seq ?? 0) + 1;
    const event = strify({
      v: EVENT_V, seq: String(seq), eventId: 'ev-' + d5hex(V5_DOMAINS.JOURNAL_EVENT, { a: this.accountId, l: layer, s: String(seq), t: String(at) }).slice(0, 24),
      layer, type: ascii(ev.type), accountId: this.accountId, principal: ev.principal ?? '-', operationDigest: ev.operationDigest ?? '-', at: iso(at),
      relatedId: ascii(ev.relatedId ?? '-'), outcome: ascii(ev.outcome ?? '-'), purposeVersion: String(ev.purposeVersion ?? '-'), epoch: String(ev.epoch ?? '-'),
      evidenceRefs: (ev.evidenceRefs ?? []).map(ascii).slice(0, 32), data: asciiDeep(ev.data ?? {}), untrusted: asciiDeep(ev.untrusted ?? {}), prevHash: prev?.hash ?? ZERO,
    });
    let sealedTxt = null;
    if (ev.sealed) { const k = this.#periodKey(period); const s = seal(k, ev.sealed, event.eventId); sealedTxt = JSON.stringify(s); event.sealedDigest = d5hex(V5_DOMAINS.JOURNAL_EVENT, s); }
    const hash = d5hex(V5_DOMAINS.JOURNAL_EVENT, event);
    const bodyTxt = JSON.stringify(event);
    this.db.prepare('INSERT INTO events (seq, event_id, layer, type, at, body, sealed, period, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)').run(seq, event.eventId, layer, event.type, at, bodyTxt, sealedTxt, period, event.prevHash, hash);
    this.stats.appended++; this.stats.bytes += bodyTxt.length + (sealedTxt?.length ?? 0);
    if (seq % this.checkpointEvery === 0 || CHECKPOINT_NOW_TYPES.has(event.type)) this.checkpoint();
    return { ...event, hash };
  }
  checkpoint() {
    const top = this.db.prepare('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get(); if (!top) return null;
    const last = this.witnesses[0].all().at(-1); if (last && Number(last.statement.seq) >= top.seq) return last;
    const statement = { v: 'safebox.v5.journal-checkpoint', accountId: this.accountId, seq: String(top.seq), head: top.hash, at: iso(this.now()), count: String(top.seq) };
    const cp = { statement, sig: this.signer.signObj(V5_DOMAINS.JOURNAL_CHECKPOINT, statement) };
    for (const w of this.witnesses) w.accept(cp);
    this.stats.checkpoints++;
    return cp;
  }
  rows() { return this.db.prepare('SELECT * FROM events ORDER BY seq').all(); }
  head() { return this.db.prepare('SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1').get() ?? { seq: 0, hash: ZERO }; }

  /** Role-based reader. The analyst never receives sealed metadata or real identities. */
  reader(role) {
    if (!['analyst', 'auditor', 'owner', 'verifier'].includes(role)) fail('JOURNAL_ROLE');
    const j = this;
    const view = (r) => {
      const e = JSON.parse(r.body);
      if (role === 'verifier') return { seq: e.seq, eventId: e.eventId, layer: e.layer, type: e.type, at: e.at, hash: r.hash, prevHash: e.prevHash };
      if (role === 'owner') e.principalName = j.reverse.get(e.principal) ?? e.principal;
      if ((role === 'auditor' || role === 'owner') && r.sealed) { const k = j.periodKeys.get(r.period); e.sealed = k ? unseal(k, JSON.parse(r.sealed), e.eventId) : 'SHREDDED'; }
      return e;
    };
    return Object.freeze({ role, events: ({ sinceSeq = 0, types = null, layer = null, limit = 5000 } = {}) => j.db.prepare('SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?').all(sinceSeq, limit)
      .filter(r => (!types || types.includes(r.type)) && (!layer || r.layer === layer)).map(view),
      head: () => j.head(), checkpoints: () => j.witnesses[0].all() });
  }
}

/** Independent verification of a journal against witness checkpoints (run by the verifier, not the journal). */
export function verifyJournalChain(rows, checkpoints, publicKey) {
  const out = { ok: true, events: rows.length, problems: [], checkpointsVerified: 0 };
  let prev = ZERO; const byS = new Map();
  rows.forEach((r, i) => {
    const e = JSON.parse(r.body);
    if (Number(e.seq) !== i + 1) out.problems.push(`gap_or_reorder_at_${i + 1}`);
    if (e.prevHash !== prev) out.problems.push(`broken_link_at_${e.seq}`);
    const h = d5hex(V5_DOMAINS.JOURNAL_EVENT, e);
    if (h !== r.hash) out.problems.push(`modified_event_${e.seq}`);
    if (r.sealed && e.sealedDigest !== d5hex(V5_DOMAINS.JOURNAL_EVENT, JSON.parse(r.sealed))) out.problems.push(`modified_sealed_${e.seq}`);
    prev = r.hash; byS.set(Number(e.seq), r.hash);
  });
  for (const cp of checkpoints) {
    if (!verifyObj5(V5_DOMAINS.JOURNAL_CHECKPOINT, cp.statement, cp.sig, publicKey)) { out.problems.push('checkpoint_bad_signature'); continue; }
    const h = byS.get(Number(cp.statement.seq));
    if (!h) out.problems.push(`checkpoint_${cp.statement.seq}_missing_events (deletion/truncation)`);
    else if (h !== cp.statement.head) out.problems.push(`checkpoint_${cp.statement.seq}_head_mismatch (tampering)`);
    else out.checkpointsVerified++;
  }
  const ids = rows.map(r => JSON.parse(r.body).eventId); if (new Set(ids).size !== ids.length) out.problems.push('duplicated_event_ids');
  out.ok = out.problems.length === 0;
  return out;
}
export { canon };
