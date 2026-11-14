// V6 notification service = the V5 outbox UNCHANGED (verified Root-pinned recipients, idempotent dedupe, bounded
// retries, flood control, sanitized text) plus:
//   * honest delivery states for a real provider: GMAIL_API_ACCEPTED (provider accepted the message), SEND_FAILED,
//     REAUTH_REQUIRED (OAuth grant revoked / expired; no retry storm), and a separate, manually attested
//     INBOX_RECEIPT_CONFIRMED. An API acceptance is never reported as delivered.
//   * the reviewed Emergency Freeze NAVIGATION link (V5's no-links policy is kept as the safe fallback, linkMode
//     'NO_LINKS'). The link is built only from the owner-signed allowlisted origin and an opaque random locator; it
//     carries no signature, approval, token, key or authority, and resolving it changes no state.
import { randomBytes, createHash } from 'node:crypto';
import { NotificationService, NOTIFY_POLICY } from '../../v5/notify/notify.mjs';

export const DELIVERY = Object.freeze({ GMAIL_API_ACCEPTED: 'GMAIL_API_ACCEPTED', INBOX_RECEIPT_CONFIRMED: 'INBOX_RECEIPT_CONFIRMED', INBOX_RECEIPT_NOT_VERIFIED: 'INBOX_RECEIPT_NOT_VERIFIED', SEND_FAILED: 'SEND_FAILED' });
export const LOCATOR_RE = /^l[0-9a-f]{32}$/;

export class IncidentLocators {
  constructor(db, { now, ttlMs }) {
    this.db = db; this.now = now; this.ttlMs = ttlMs;
    db.exec(`CREATE TABLE IF NOT EXISTS locators (locator TEXT PRIMARY KEY, incident TEXT NOT NULL, outbox_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);`);
  }
  create(incidentId, outboxId = null) {
    const loc = 'l' + randomBytes(16).toString('hex'); // 128-bit opaque, unguessable; NOT an authorization token
    this.db.prepare('INSERT INTO locators (locator, incident, outbox_id, created_at, expires_at) VALUES (?,?,?,?,?)').run(loc, incidentId, outboxId, this.now(), this.now() + this.ttlMs);
    return loc;
  }
  /** Read-only resolution: never updates, consumes or logs anything into security state. */
  resolve(locator) {
    if (typeof locator !== 'string' || !LOCATOR_RE.test(locator)) return { ok: false, code: 'LOCATOR_MALFORMED' };
    const r = this.db.prepare('SELECT incident, expires_at FROM locators WHERE locator=?').get(locator);
    if (!r) return { ok: false, code: 'LOCATOR_UNKNOWN' };
    if (this.now() >= r.expires_at) return { ok: false, code: 'LOCATOR_EXPIRED', incidentId: r.incident };
    return { ok: true, incidentId: r.incident };
  }
}

export class NotificationServiceV6 extends NotificationService {
  constructor(opts) {
    super(opts);
    this.emergencyOrigin = opts.emergencyOrigin ?? null; this.linkMode = opts.linkMode ?? (this.emergencyOrigin ? 'NAVIGATION_LINK' : 'NO_LINKS');
    this.locators = new IncidentLocators(this.db, { now: this.now, ttlMs: opts.locatorTtlMs ?? 72 * 3600_000 });
    this.db.exec(`CREATE TABLE IF NOT EXISTS receipts (outbox_id TEXT PRIMARY KEY, observed_at INTEGER NOT NULL, method TEXT NOT NULL, evidence_hash TEXT NOT NULL, attested_by TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sends (n INTEGER PRIMARY KEY AUTOINCREMENT, outbox_id TEXT NOT NULL, at INTEGER NOT NULL, status TEXT NOT NULL, meta TEXT NOT NULL);`);
    try { this.db.exec('ALTER TABLE outbox ADD COLUMN locator TEXT'); } catch {}
  }
  /** Fixed, reviewed emergency link line: only the owner-signed origin and an opaque locator (no other URL ever). */
  emergencyLine(locator) { return `Emergency Freeze (opens SafeBox; NOTHING is frozen until you confirm there with your enrolled device and fingerprint): ${this.emergencyOrigin}/e/${locator}`; }
  enqueue(rootState, args) {
    const before = new Set(this.db.prepare('SELECT id FROM outbox').all().map(r => r.id));
    const out = super.enqueue(rootState, args);
    if (this.linkMode === 'NAVIGATION_LINK' && (args.kind ?? 'INCIDENT') === 'INCIDENT' && /^https?:\/\/[a-z0-9.:-]+$/.test(String(this.emergencyOrigin))) {
      for (const r of this.db.prepare("SELECT id, body FROM outbox WHERE incident=? AND kind='INCIDENT' AND state='QUEUED'").all(args.incident.incidentId)) {
        if (before.has(r.id)) continue;
        const loc = this.locators.create(args.incident.incidentId, r.id);
        // replaces V5's "do not use links" line by an explicit navigation-only statement; everything else is unchanged
        const body = r.body.replace('open the SafeBox app you enrolled (do not use links in emails)', 'open the SafeBox app you enrolled, or use the Emergency Freeze link below (it only opens SafeBox)')
          .replace('SafeBox never asks you to reply, click a link, or send a code by email.', 'SafeBox never asks you to reply or send a code by email, and no link can approve, release or freeze anything by itself.')
          + '\n' + this.emergencyLine(loc) + '\nThis link carries no approval: SafeBox will ask you to sign in, show the incident from its own records, and require your enrolled device before anything changes.';
        this.db.prepare('UPDATE outbox SET body=?, locator=? WHERE id=?').run(body, loc, r.id);
      }
    }
    return out;
  }
  /** Delivery worker with provider-honest states. MockTransport keeps its V5 meaning (DELIVERED = mock delivery). */
  async drain() {
    const out = { delivered: 0, accepted: 0, failed: 0, retry: 0, notConnected: 0, reauth: 0 };
    for (const r of this.db.prepare("SELECT * FROM outbox WHERE state IN ('QUEUED','RETRY') AND next_at<=? ORDER BY created_at").all(this.now())) {
      const address = [...this.book.values()].flat().find(x => x.ref === r.contact_ref)?.address;
      let res; try { res = await this.transport.send({ to: address, subject: r.subject, text: r.body, idempotencyKey: r.dedupe }); } catch (e) { res = { status: 'TEMPORARY_FAILURE', error: String(e.message).slice(0, 80) }; }
      const attempts = r.attempts + 1;
      this.db.prepare('INSERT INTO sends (outbox_id, at, status, meta) VALUES (?,?,?,?)').run(r.id, this.now(), res.status, JSON.stringify(res.meta ?? {}));
      if (res.status === 'DELIVERED') { this.db.prepare("UPDATE outbox SET state='DELIVERED', attempts=?, provider_id=?, delivered_at=? WHERE id=?").run(attempts, res.providerId, this.now(), r.id); out.delivered++; }
      else if (res.status === 'ACCEPTED') { this.db.prepare("UPDATE outbox SET state='API_ACCEPTED', attempts=?, provider_id=?, delivered_at=NULL WHERE id=?").run(attempts, res.providerId, r.id); out.accepted++; }
      else if (res.status === 'NOT_CONNECTED') { this.db.prepare("UPDATE outbox SET state='NOT_CONNECTED', attempts=?, last_error=? WHERE id=?").run(attempts, res.error, r.id); out.notConnected++; }
      else if (res.status === 'AUTH_FAILED') { this.db.prepare("UPDATE outbox SET state='REAUTH_REQUIRED', attempts=?, last_error=? WHERE id=?").run(attempts, res.error, r.id); out.reauth++; }
      else if (res.status === 'TEMPORARY_FAILURE' && attempts < NOTIFY_POLICY.maxAttempts) { this.db.prepare("UPDATE outbox SET state='RETRY', attempts=?, next_at=?, last_error=? WHERE id=?").run(attempts, this.now() + NOTIFY_POLICY.backoffMs[attempts - 1], res.error, r.id); out.retry++; }
      else { this.db.prepare("UPDATE outbox SET state='FAILED', attempts=?, last_error=? WHERE id=?").run(attempts, res.error ?? res.status, r.id); out.failed++; }
      this.journal?.append({ type: 'NOTIFICATION_ATTEMPT', relatedId: r.incident, outcome: res.status, data: { contact: r.contact_ref.slice(0, 16), attempt: String(attempts), kind: r.kind, transport: String(this.transport.kind ?? '-') } });
    }
    return out;
  }
  /** Operator re-authenticated the Gmail grant: REAUTH_REQUIRED rows go back to the queue (dedupe keys unchanged). */
  requeueAfterReauth() { return this.db.prepare("UPDATE outbox SET state='RETRY', next_at=? WHERE state='REAUTH_REQUIRED'").run(this.now()).changes; }
  /** Manual, operator-attested inbox receipt (consenting test mailbox). Evidence is reduced to a hash. */
  attestReceipt(outboxId, { observedAt, method = 'MANUAL_OPERATOR_ATTESTATION', evidence, attestedBy = 'operator' }) {
    const r = this.db.prepare('SELECT state FROM outbox WHERE id=?').get(outboxId);
    if (!r || r.state !== 'API_ACCEPTED') throw Object.assign(new Error('receipt only after GMAIL_API_ACCEPTED'), { code: 'RECEIPT_WITHOUT_ACCEPTANCE' });
    this.db.prepare('INSERT INTO receipts (outbox_id, observed_at, method, evidence_hash, attested_by) VALUES (?,?,?,?,?)').run(outboxId, observedAt, method, createHash('sha256').update(String(evidence)).digest('hex'), attestedBy);
  }
  deliveryStatus(outboxId) {
    const r = this.db.prepare('SELECT state FROM outbox WHERE id=?').get(outboxId);
    if (!r) return null;
    const rc = this.db.prepare('SELECT * FROM receipts WHERE outbox_id=?').get(outboxId);
    if (r.state === 'API_ACCEPTED') return { api: DELIVERY.GMAIL_API_ACCEPTED, inbox: rc ? DELIVERY.INBOX_RECEIPT_CONFIRMED : DELIVERY.INBOX_RECEIPT_NOT_VERIFIED, receipt: rc ?? null };
    if (r.state === 'DELIVERED') return { api: 'MOCK_DELIVERED', inbox: DELIVERY.INBOX_RECEIPT_NOT_VERIFIED, receipt: null };
    if (['FAILED', 'REAUTH_REQUIRED'].includes(r.state)) return { api: DELIVERY.SEND_FAILED, inbox: DELIVERY.INBOX_RECEIPT_NOT_VERIFIED, state: r.state };
    return { api: r.state, inbox: DELIVERY.INBOX_RECEIPT_NOT_VERIFIED };
  }
  outbox() { return this.db.prepare('SELECT id, incident, kind, contact_ref, holders, subject, state, attempts, created_at, delivered_at, last_error, provider_id, locator FROM outbox ORDER BY created_at').all(); }
  messageBody(outboxId) { return this.db.prepare('SELECT body FROM outbox WHERE id=?').get(outboxId)?.body ?? null; }
}
