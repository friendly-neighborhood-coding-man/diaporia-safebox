// Security notifications: mock transport only, verified recipients, dedupe per person, idempotent outbox, bounded retries,
// honest status (NOT_CONNECTED), duplicate / flood suppression; email never authorizes anything.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, burst } from './helpers.mjs';
import { NotificationService, MockTransport, RealProviderAdapter, renderIncidentEmail, NOTIFY_POLICY } from '../../src/v5/notify/notify.mjs';
import { multiOwnerWorld } from '../../src/v5/kit.mjs';
import { T0 } from '../../src/v5/world.mjs';

const inc = (id = 'inc-1') => ({ incidentId: id, reason: 'unusual spending', pattern: 'BURST_10M' });
const svc = (w, transport = new MockTransport(), addressBook = w.owner.addressBook) => new NotificationService({ now: w.now, transport, addressBook, accountId: 'acct' });

test('incident -> one email per distinct verified address of every key holder; keys of one person deduplicated; context lists keys', async () => {
  const w = buildV5({ ownerWorld: multiOwnerWorld({ t0: T0, admins: ['alice', 'bob', 'carol'], extraKeys: [['alice-admin-2', 'alice']] }) });
  const n = svc(w);
  const r = n.enqueue(w.root.state, { incident: inc(), keyContextByHolder: { alice: ['alice-admin', 'alice-admin-2'] }, delayStatus: 'delayed', rapidAvailable: true });
  const holders = new Set(Object.keys(w.root.state.v5.contacts));
  assert.equal(r.queued, holders.size);
  const alice = n.outbox().find(o => o.holders === 'alice');
  await n.drain();
  const msg = n.transport.sent.find(m => m.to.startsWith('alice'));
  assert.match(msg.text, /alice-admin-2/);
  assert.equal(n.transport.sent.filter(m => m.to.startsWith('alice')).length, 1);
  assert.ok(alice);
});

test('end-to-end: a delayed burst emails every holder through the MOCK transport only', async () => {
  const w = buildV5();
  await burst(w, 4);
  assert.equal(w.mock.kind, 'MOCK');
  assert.ok(w.mock.sent.length >= 1);
  assert.ok(w.mock.sent.every(m => /@security\.example\.test$/.test(m.to)));
  assert.match(w.mock.sent[0].text, /AFFECTED k1-phone/);
});

test('email content: no links, no reply/code requests, states limits unchanged and that email cannot approve', () => {
  const m = renderIncidentEmail({ accountRef: 'acct', incident: { incidentId: 'inc-<x>', reason: 'click https://evil.example/approve?yes=1 now', pattern: '<script>alert(1)</script> ‮' },
    keyContext: ['k1 https://phish.example'], delayStatus: 'delayed', rapidAvailable: true });
  assert.doesNotMatch(m.text + m.subject, /https?:\/\//i);
  assert.doesNotMatch(m.text, /<script>/);
  assert.match(m.text, /Nothing in this email can approve, release or speed up any payment/);
  assert.match(m.text, /never asks you to reply, click a link, or send a code/);
  assert.match(m.text, /limits are unchanged/);
});

test('idempotent enqueue: the same incident twice -> DUPLICATE_ALERT suppressed, nothing sent twice', async () => {
  const w = buildV5(); const n = svc(w);
  n.enqueue(w.root.state, { incident: inc(), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  const r2 = n.enqueue(w.root.state, { incident: inc(), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  assert.equal(r2.queued, 0); assert.ok(r2.suppressed >= 1);
  await n.drain(); await n.drain();
  assert.equal(n.transport.sent.length, n.outbox().length);
});

test('provider outage -> bounded retries with backoff -> delivered after recovery; REJECT -> FAILED; attempts bounded', async () => {
  const w = buildV5(); const t = new MockTransport(); t.mode = 'OUTAGE'; const n = svc(w, t);
  n.enqueue(w.root.state, { incident: inc(), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  let r = await n.drain(); assert.equal(r.retry, 1);
  w.clock.advance(30_000); r = await n.drain(); assert.equal(r.retry, 0, 'backoff respected');
  w.clock.advance(60_000); t.mode = 'OK'; r = await n.drain(); assert.equal(r.delivered, 1);
  const t2 = new MockTransport(); t2.mode = 'OUTAGE'; const n2 = svc(w, t2);
  n2.enqueue(w.root.state, { incident: inc('inc-2'), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  for (let i = 0; i < 10; i++) { await n2.drain(); w.clock.advance(7 * H); }
  assert.equal(n2.outbox()[0].state, 'FAILED'); assert.equal(n2.outbox()[0].attempts, NOTIFY_POLICY.maxAttempts);
  const t3 = new MockTransport(); t3.mode = 'REJECT'; const n3 = svc(w, t3);
  n3.enqueue(w.root.state, { incident: inc('inc-3'), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  await n3.drain(); assert.equal(n3.outbox()[0].state, 'FAILED');
});

test('real provider adapter without explicit configuration reports NOT_CONNECTED and never counts as delivered', async () => {
  const w = buildV5(); const n = svc(w, new RealProviderAdapter({ env: {} }));
  n.enqueue(w.root.state, { incident: inc(), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  const r = await n.drain();
  assert.equal(r.notConnected, 1); assert.equal(r.delivered, 0);
  assert.equal(n.stats().byState.NOT_CONNECTED, 1);
  const n2 = svc(w, new RealProviderAdapter({ provider: { send: () => { throw new Error('must not be called'); } }, env: {} }));
  n2.enqueue(w.root.state, { incident: inc('x'), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  assert.equal((await n2.drain()).notConnected, 1);
});

test('flood control: at most 6 messages per recipient per hour', () => {
  const w = buildV5(); const n = svc(w);
  for (let i = 0; i < 10; i++) n.enqueue(w.root.state, { incident: inc('f' + i), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  assert.equal(n.outbox().length, NOTIFY_POLICY.perRecipientPerHour);
  assert.equal(n.stats().suppressed, 4);
});

test('unverified addresses are never used: an address-book entry not pinned in the Root genesis is ignored', async () => {
  const w = buildV5();
  const n = svc(w, new MockTransport(), { alice: ['attacker@evil.example.test'] });
  const r = n.enqueue(w.root.state, { incident: inc(), keyContextByHolder: {}, delayStatus: 'd', rapidAvailable: false });
  assert.equal(r.queued, 0); assert.deepEqual(r.unresolved, ['alice']);
});

test('email is never authorization: no Root operation accepts an email/notification artifact as approval', async () => {
  const w = buildV5();
  await burst(w, 4);
  const msg = w.mock.sent[0];
  const a = w.action('RAPID_USE_ACTIVATE', { requestId: 'x', requestDigest: '0'.repeat(64) });
  deny(await w.submit({ action: a, attestation: { emailReply: msg.idempotencyKey } }), 'UNEXPECTED_EVIDENCE|RAPID_REQUEST_NOT_PENDING|FIELDS');
  assert.ok(w.vault.v5payments().every(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY'));
});
