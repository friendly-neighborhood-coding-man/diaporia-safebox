// Rapid-Use Mode: exact scope, quorum (personal enhanced ceremony / multi-owner max(2, ceil(N/2)) distinct humans),
// <= 24 h from activation, early termination, deterministic engine termination, never a Purpose expansion.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, D, Y, scopeOf, rapidRequest, rapidVote, rapidActivate, burst, freezeBy } from './helpers.mjs';
import { multiOwnerWorld } from '../../src/v5/kit.mjs';
import { T0 } from '../../src/v5/world.mjs';

const delayed = (w) => w.vault.v5payments().filter(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY' && p.state === 'BUFFERED');

test('personal: anomaly delay -> owner requests Rapid-Use -> ORC + separate owner credential -> delayed payments released, limits unchanged', async () => {
  const w = buildV5();
  await burst(w, 5);
  assert.ok(delayed(w).length >= 3);
  const inc = w.vault.incidents()[0].incident_id;
  ok(await rapidRequest(w, 'k1-phone', { incidentId: inc }));
  deny(await rapidActivate(w), 'RAPID_QUORUM_NOT_MET');
  ok(await rapidVote(w, 'orc-1'));
  deny(await rapidVote(w, 'k1-phone'), 'RAPID_FACTOR_IS_AFFECTED_CREDENTIAL|TRUSTED_CONFIRMATION_REQUIRED');
  deny(await rapidVote(w, 'k2-laptop'), 'TRUSTED_CONFIRMATION_REQUIRED');      // software-only UI is not enough
  ok(await rapidVote(w, 'k3-root-hw'));
  ok(await rapidActivate(w));
  await w.advance(11 * 60_000);
  const ps = w.vault.v5payments();
  assert.equal(ps.filter(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY' && p.state === 'BUFFERED').length, 0);
  assert.ok(ps.filter(p => p.anomaly === 'RELEASED_BY_RAPID' && p.state === 'SETTLED').length >= 3);
  assert.equal(w.root.state.purpose.perPaymentMaxYocto, scopeOf(w).perPaymentMaxYocto);
  // still bound by Purpose: over-limit and unknown recipients refused during Rapid-Use
  assert.equal((await w.pay({ amountYocto: Y(7) })).ok, false);
  assert.equal((await w.pay({ recipientId: 'attacker.mock' })).ok, false);
});

test('Rapid-Use can never enlarge Purpose: scope must restate exact limits and Purpose recipients', async () => {
  const w = buildV5();
  const s = scopeOf(w);
  deny(await rapidRequest(w, 'k1-phone', { scope: { ...s, perPaymentMaxYocto: Y(100) } }), 'RAPID_SCOPE_LIMITS_MUST_EQUAL_PURPOSE');
  deny(await rapidRequest(w, 'k1-phone', { scope: { ...s, recipients: ['attacker.mock'] } }), 'RAPID_SCOPE_RECIPIENT_NOT_IN_PURPOSE');
  deny(await rapidRequest(w, 'k1-phone', { scope: { ...s, purposeVersion: '99' } }), 'RAPID_SCOPE_PURPOSE_MISMATCH');
  deny(await rapidRequest(w, 'k1-phone', { durationMs: 25 * H }), 'RAPID_DURATION_MAX_24H');
  deny(await rapidRequest(w, 'k1-phone', { scope: { ...s, credIds: ['k3-root-hw'] } }), 'RAPID_SCOPE_CREDENTIAL');
});

test('window starts at activation, ends at <= 24 h, never auto-renews; a new window needs a fresh request', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone', { durationMs: 24 * H }));
  ok(await rapidVote(w, 'orc-1'));
  await w.advance(30 * 60_000);
  ok(await rapidVote(w, 'k3-root-hw'));
  const t = w.now();
  ok(await rapidActivate(w));
  const g = w.root.state.v5.rapid.grants['rq-1'];
  assert.equal(Number(g.expiresAt), t + 24 * H);
  await w.advance(24 * H + 60_000, H);
  assert.equal(w.root.state.v5.rapid.grants['rq-1'].status, 'EXPIRED');
  deny(await rapidActivate(w), 'RAPID_REQUEST_NOT_PENDING');
  deny(await rapidRequest(w, 'k1-phone'), 'RAPID_REQUEST_ID_REUSED');
});

test('approval window: votes expire after 1 h; stale request cannot be activated', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone'));
  ok(await rapidVote(w, 'orc-1'));
  await w.advance(61 * 60_000);
  deny(await rapidVote(w, 'k3-root-hw'), 'RAPID_REQUEST_(APPROVAL_WINDOW_CLOSED|NOT_PENDING)');
  deny(await rapidActivate(w), 'RAPID_REQUEST_(APPROVAL_WINDOW_CLOSED|NOT_PENDING)');
});

test('"End Rapid-Use Mode": the ORC, an approver or the covered credential ends it immediately; unrelated cred cannot', async () => {
  for (const ender of ['orc-1', 'k3-root-hw', 'k1-phone']) {
    const w = buildV5();
    ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
    deny(await w.cmd('RAPID_USE_REVOKE', { grantId: 'rq-1', reason: 'x' }, ['k4-freeze']), 'RAPID_REVOKE_NOT_ENTITLED');
    ok(await w.cmd('RAPID_USE_REVOKE', { grantId: 'rq-1', reason: 'End Rapid-Use Mode' }, [ender]));
    assert.equal(w.root.state.v5.rapid.grants['rq-1'].status, 'REVOKED');
  }
});

test('deterministic termination: hold on the covered credential / epoch change ends the grant; monitoring continues; velocity ceiling ends it via engine attestation', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  ok(await w.cmd('SUSPEND', { credId: 'k1-phone', holdId: 'q1' }, ['k2-laptop']));
  assert.equal(w.root.state.v5.rapid.grants['rq-1'].status, 'ENDED_CREDENTIAL_RESTRICTED');

  const w2 = buildV5();
  ok(await rapidRequest(w2, 'k1-phone')); ok(await rapidVote(w2, 'orc-1')); ok(await rapidVote(w2, 'k3-root-hw')); ok(await rapidActivate(w2));
  // 31 payments inside one hour: the hard ceiling (30/h) still applies during Rapid-Use -> engine ends the grant
  let n = 0;
  for (let i = 0; i < 40 && w2.root.state.v5.rapid.grants['rq-1'].status === 'ACTIVE'; i++) { const r = await w2.pay({ amountYocto: Y(1) }); if (r.ok) n++; await w2.advance(60_000, 60_000); }
  const g = w2.root.state.v5.rapid.grants['rq-1'];
  assert.equal(g.status, 'REVOKED', `after ${n} payments`);
  assert.match(g.endedBy, /^risk-engine:R3_VELOCITY_CEILING/);
  const evs = w2.journal.reader('auditor').events({ types: ['UNUSUAL_ACTIVITY_DETECTED'] });
  assert.ok(evs.length >= 1, 'monitoring continued during Rapid-Use');
  // Rapid-Use payments never train the baseline
  assert.ok(w2.vault.history().filter(h => h.paymentId && w2.vault.v5payments().find(p => p.payment_id === h.paymentId)?.rapid_grant).every(h => !h.baselineEligible));
});

test('request abuse: per-credential rate limit and one pending request per credential', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone', { id: 'a1' }));
  deny(await rapidRequest(w, 'k1-phone', { id: 'a2' }), 'RAPID_REQUEST_ALREADY_PENDING');
  await w.advance(61 * 60_000, 10 * 60_000);
  ok(await rapidRequest(w, 'k1-phone', { id: 'a3' }));
  await w.advance(61 * 60_000, 10 * 60_000);
  ok(await rapidRequest(w, 'k1-phone', { id: 'a4' }));
  await w.advance(61 * 60_000, 10 * 60_000);
  deny(await rapidRequest(w, 'k1-phone', { id: 'a5' }), 'RAPID_REQUEST_RATE_LIMIT');
  ok(await rapidRequest(w, 'k2-laptop', { id: 'b1', scope: scopeOf(w, { credIds: ['k2-laptop'] }) })); // a thief's key cannot exhaust the owner's other keys
});

test('a frozen vault stays frozen during Rapid-Use (no hold is bypassed)', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  ok(await freezeBy(w, 'k4-freeze'));
  assert.equal((await w.pay({})).ok, false);
});

// ---------------------------------------------------------------- multi-owner quorum
const multi = (admins, extraKeys = []) => buildV5({ ownerWorld: multiOwnerWorld({ t0: T0, admins, extraKeys }) });
const mscope = (w, cred) => scopeOf(w, { credIds: [cred] });

for (const [n, need] of [[3, 2], [4, 2], [5, 3], [6, 3]]) test(`multi-owner N=${n}: quorum = max(2, ceil(N/2)) = ${need} distinct humans`, async () => {
  const admins = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace'].slice(0, n);
  const w = multi(admins);
  ok(await rapidRequest(w, 'alice-admin', { scope: mscope(w, 'alice-admin') }));
  for (let i = 0; i < need - 1; i++) ok(await rapidVote(w, admins[i] + '-admin'));
  deny(await rapidActivate(w), 'RAPID_QUORUM_NOT_MET');
  ok(await rapidVote(w, admins[need - 1] + '-admin'));
  ok(await rapidActivate(w));
});

test('multi-owner: several keys of one human are one vote; non-owner roles and the ORC cannot vote', async () => {
  const w = multi(['alice', 'bob', 'carol', 'dave'], [['alice-admin-2', 'alice']]);
  ok(await rapidRequest(w, 'bob-admin', { scope: mscope(w, 'bob-admin') }));
  ok(await rapidVote(w, 'alice-admin'));
  deny(await rapidVote(w, 'alice-admin-2'), 'RAPID_DUPLICATE_PRINCIPAL_VOTE');
  deny(await rapidVote(w, 'ops-freeze'), 'RAPID_VOTER_NOT_OWNER_PRINCIPAL');
  deny(await rapidActivate(w), 'RAPID_QUORUM_NOT_MET');
});

test('multi-owner: a suspended owner cannot vote and a vote of an owner suspended before activation no longer counts; suspension never shrinks N', async () => {
  const w = multi(['alice', 'bob', 'carol', 'dave', 'erin']); // N=5 -> 3
  ok(await rapidRequest(w, 'alice-admin', { scope: mscope(w, 'alice-admin') }));
  ok(await rapidVote(w, 'alice-admin')); ok(await rapidVote(w, 'bob-admin')); ok(await rapidVote(w, 'carol-admin'));
  ok(await w.cmd('SUSPEND', { credId: 'carol-admin', holdId: 'q-c' }, ['dave-admin']));
  deny(await rapidVote(w, 'carol-admin'), 'CREDENTIAL|SUSPENDED|NOT_ACTIVE');
  deny(await rapidActivate(w), 'RAPID_QUORUM_NOT_MET:2/3');
  ok(await rapidVote(w, 'erin-admin'));
  ok(await rapidActivate(w));
});
