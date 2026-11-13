// V5 security notifications. STRICTLY SEPARATE from authorization: nothing in this module can approve, release,
// accelerate or authorize anything, and no other module accepts anything from it as approval. Email delivery,
// opening, clicking or replying never counts as consent; the message points the person to their independently
// trusted SafeBox confirmation path and contains no approval link.
// Delivery: verified recipients only (contact digests pinned in the Root genesis), auditable outbox, idempotent sends
// (unique dedupe key per incident x recipient x kind), bounded retries with backoff, delivery-status accounting,
// provider-outage handling, duplicate-alert suppression and per-recipient flood control.
// Transports: MockTransport (all tests and campaigns) and RealProviderAdapter, which reports NOT_CONNECTED unless a
// provider is explicitly configured AND SAFEBOX_ALLOW_REAL_EMAIL=1 — never set in experiments.
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { fail, iso } from '../../v3/common/canon.mjs';
import { contactRefOf } from '../kit.mjs';

export const NOTIFY_POLICY = Object.freeze({ maxAttempts: 5, backoffMs: [60_000, 300_000, 900_000, 3600_000, 6 * 3600_000], perRecipientPerHour: 6, duplicateWindowMs: 6 * 3600_000 });
const clean = (s, n = 120) => String(s ?? '').replace(/[^\x20-\x7e]/g, '?').replace(/[<>`]/g, '?').replace(/https?:\/\/\S+/gi, '[link removed]').slice(0, n);

export class MockTransport {
  constructor() { this.sent = []; this.mode = 'OK'; this.delayMs = 0; this.duplicate = false; this.kind = 'MOCK'; }
  async send(msg) {
    if (this.mode === 'OUTAGE') return { status: 'TEMPORARY_FAILURE', error: 'PROVIDER_OUTAGE' };
    if (this.mode === 'REJECT') return { status: 'PERMANENT_FAILURE', error: 'MAILBOX_UNAVAILABLE' };
    const providerId = 'mock-' + randomUUID();
    this.sent.push({ ...msg, providerId, deliveredAfterMs: this.delayMs });
    if (this.duplicate) this.sent.push({ ...msg, providerId, duplicate: true });
    return { status: 'DELIVERED', providerId };
  }
}
export class RealProviderAdapter {
  constructor({ provider = null, env = process.env } = {}) { this.provider = provider; this.allowed = env.SAFEBOX_ALLOW_REAL_EMAIL === '1'; this.kind = 'REAL'; }
  async send() {
    if (!this.provider || !this.allowed) return { status: 'NOT_CONNECTED', error: 'no production email provider configured (or SAFEBOX_ALLOW_REAL_EMAIL!=1); nothing was sent' };
    return this.provider.send(...arguments);
  }
}

/** Deterministic notification text. Untrusted fields (merchant / memo) are sanitized and quoted; no links of any kind. */
export function renderIncidentEmail({ accountRef, incident, keyContext, delayStatus, rapidAvailable, kind = 'INCIDENT' }) {
  const subject = kind === 'INCIDENT' ? `SafeBox security alert ${clean(incident.incidentId, 40)}: unusual spending was delayed`
    : kind === 'RAPID_USE' ? `SafeBox: Rapid-Use approval requested (${clean(incident.incidentId, 40)})` : `SafeBox security report ${clean(incident.incidentId, 40)}`;
  const lines = [
    `SafeBox account: ${clean(accountRef, 40)}`, `Incident: ${clean(incident.incidentId, 40)}`, `Reason: ${clean(incident.reason, 200)}`,
    ...keyContext.map(k => `Affected credential / capability: ${clean(k, 80)}`),
    `Observed pattern: ${clean(incident.pattern, 300)}`, `Payment delay status: ${clean(delayStatus, 160)}`,
    'Your Purpose, recipients and spending limits are unchanged. Nothing in this email can approve, release or speed up any payment.',
    'Safe next steps: open the SafeBox app you enrolled (do not use links in emails), review the incident there, and use your enrolled authenticator if you want to act.',
    rapidAvailable ? 'If this spending is yours and urgent, you can request Rapid-Use Mode (max 24 h, same limits) from the SafeBox app; it needs your independent approvals.' : 'Rapid-Use Mode is not available for this incident.',
    'SafeBox never asks you to reply, click a link, or send a code by email.',
  ];
  return { subject, text: lines.join('\n') };
}

export class NotificationService {
  constructor({ path = ':memory:', now, transport, addressBook, journal = null, accountId }) {
    this.db = new DatabaseSync(path); this.now = now; this.transport = transport; this.journal = journal; this.accountId = accountId;
    // address book: encrypted-at-rest in a real deployment; here an in-process map of mock addresses on a reserved test domain
    this.book = new Map(); for (const [h, list] of Object.entries(addressBook)) this.book.set(h, list.map(a => ({ address: a, ref: contactRefOf(a) })));
    this.db.exec(`CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, dedupe TEXT NOT NULL UNIQUE, incident TEXT NOT NULL, kind TEXT NOT NULL, contact_ref TEXT NOT NULL,
      holders TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL, next_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
      last_error TEXT, provider_id TEXT, delivered_at INTEGER);
      CREATE TABLE IF NOT EXISTS suppressed (n INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, incident TEXT NOT NULL, contact_ref TEXT NOT NULL, why TEXT NOT NULL);`);
  }
  /**
   * Queue one message per DISTINCT verified address of every registered key holder (Root contacts). Addresses shared
   * by several keys of one person are deduplicated; the key-specific context is kept in the body.
   * rootState: the verified Root replica (contacts are pinned there; an address not pinned is never used).
   */
  enqueue(rootState, { incident, kind = 'INCIDENT', keyContextByHolder, delayStatus, rapidAvailable }) {
    const out = { queued: 0, suppressed: 0, recipients: [], unresolved: [] };
    const byRef = new Map();
    for (const [holderId, contacts] of Object.entries(rootState.v5.contacts)) for (const c of contacts) {
      const entry = (this.book.get(holderId) ?? []).find(x => x.ref === c.contactRef);
      if (!entry) { out.unresolved.push(holderId); continue; }
      const e = byRef.get(c.contactRef) ?? { address: entry.address, holders: new Set(), keys: [] };
      e.holders.add(holderId); e.keys.push(...(keyContextByHolder[holderId] ?? [`all keys of ${holderId}`])); byRef.set(c.contactRef, e);
    }
    for (const [ref, e] of byRef) {
      const dedupe = createHash('sha256').update(`${incident.incidentId}|${kind}|${ref}`).digest('hex');
      if (this.db.prepare('SELECT 1 FROM outbox WHERE dedupe=?').get(dedupe)) { out.suppressed++; this.db.prepare('INSERT INTO suppressed (at, incident, contact_ref, why) VALUES (?,?,?,?)').run(this.now(), incident.incidentId, ref, 'DUPLICATE_ALERT'); continue; }
      const recent = this.db.prepare('SELECT COUNT(*) n FROM outbox WHERE contact_ref=? AND created_at>?').get(ref, this.now() - 3600_000).n;
      if (recent >= NOTIFY_POLICY.perRecipientPerHour) { out.suppressed++; this.db.prepare('INSERT INTO suppressed (at, incident, contact_ref, why) VALUES (?,?,?,?)').run(this.now(), incident.incidentId, ref, 'RECIPIENT_FLOOD_LIMIT'); continue; }
      const m = renderIncidentEmail({ accountRef: this.accountId, incident, keyContext: [...new Set(e.keys)], delayStatus, rapidAvailable, kind });
      this.db.prepare('INSERT INTO outbox (id, dedupe, incident, kind, contact_ref, holders, subject, body, state, attempts, next_at, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        .run('n-' + randomUUID(), dedupe, incident.incidentId, kind, ref, [...e.holders].join(','), m.subject, m.text, 'QUEUED', 0, this.now(), this.now());
      out.queued++; out.recipients.push({ contactRef: ref, holders: [...e.holders] });
    }
    this.journal?.append({ type: 'NOTIFICATION_QUEUED', relatedId: incident.incidentId, outcome: `queued=${out.queued} suppressed=${out.suppressed}`, data: { kind, recipients: String(byRef.size), unresolvedHolders: out.unresolved.join(',') || '-' } });
    return out;
  }
  /** Delivery worker: idempotent, bounded retries, honest status (a transport that is NOT_CONNECTED never counts as delivered). */
  async drain() {
    const out = { delivered: 0, failed: 0, retry: 0, notConnected: 0 };
    for (const r of this.db.prepare("SELECT * FROM outbox WHERE state IN ('QUEUED','RETRY') AND next_at<=? ORDER BY created_at").all(this.now())) {
      const address = [...this.book.values()].flat().find(x => x.ref === r.contact_ref)?.address;
      let res; try { res = await this.transport.send({ to: address, subject: r.subject, text: r.body, idempotencyKey: r.dedupe }); } catch (e) { res = { status: 'TEMPORARY_FAILURE', error: String(e.message).slice(0, 80) }; }
      const attempts = r.attempts + 1;
      if (res.status === 'DELIVERED') { this.db.prepare("UPDATE outbox SET state='DELIVERED', attempts=?, provider_id=?, delivered_at=? WHERE id=?").run(attempts, res.providerId, this.now(), r.id); out.delivered++; }
      else if (res.status === 'NOT_CONNECTED') { this.db.prepare("UPDATE outbox SET state='NOT_CONNECTED', attempts=?, last_error=? WHERE id=?").run(attempts, res.error, r.id); out.notConnected++; }
      else if (res.status === 'TEMPORARY_FAILURE' && attempts < NOTIFY_POLICY.maxAttempts) { this.db.prepare("UPDATE outbox SET state='RETRY', attempts=?, next_at=?, last_error=? WHERE id=?").run(attempts, this.now() + NOTIFY_POLICY.backoffMs[attempts - 1], res.error, r.id); out.retry++; }
      else { this.db.prepare("UPDATE outbox SET state='FAILED', attempts=?, last_error=? WHERE id=?").run(attempts, res.error ?? res.status, r.id); out.failed++; }
      this.journal?.append({ type: 'NOTIFICATION_ATTEMPT', relatedId: r.incident, outcome: res.status, data: { contact: r.contact_ref.slice(0, 16), attempt: String(attempts), kind: r.kind } });
    }
    return out;
  }
  stats() {
    const by = Object.fromEntries(this.db.prepare('SELECT state, COUNT(*) n FROM outbox GROUP BY state').all().map(r => [r.state, r.n]));
    const attempts = this.db.prepare('SELECT COALESCE(SUM(attempts),0) n FROM outbox').get().n;
    return { byState: by, attempts, suppressed: this.db.prepare('SELECT COUNT(*) n FROM suppressed').get().n };
  }
  outbox() { return this.db.prepare('SELECT id, incident, kind, contact_ref, holders, subject, state, attempts, created_at, delivered_at, last_error FROM outbox ORDER BY created_at').all(); }
}
