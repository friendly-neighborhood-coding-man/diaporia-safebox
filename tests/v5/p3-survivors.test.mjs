// V5.1 P3: the two V5 mutation survivors.
//  (1) command challenge single-use  (command.mjs: CHALLENGE_ALREADY_CONSUMED)
//  (2) Rapid-Use skips grants whose scope names a restricted credential  (vault.mjs: rapidGrantFor)
// System-level tests (replay, restart, concurrency, flow scope) show which OTHER path stops each attack; layer-isolation
// tests remove that other path in the fixture and show that the surviving check, alone, still stops it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, Y, burst, rapidRequest, rapidVote, rapidActivate, scopeOf } from './helpers.mjs';
import { applyTransition } from '../../src/v5/root/chain.mjs';

const MIN = 60_000;
const req = (w, type, body, creds) => { const a = w.action(type, body); return { action: a, approvals: w.owner.authorize5(w.root.state, a, creds, { at: w.now() }) }; };
const holdBody = (id) => ({ holdId: id, class: 'PROVISIONAL_HOLD', scope: { kind: 'MERCHANT', target: 'merchant-c.mock' }, reason: 'suspicious merchant', durationMs: String(2 * H) });

test('P3/challenge: an accepted command replayed verbatim is refused (ACTION_REPLAY), also after a Root restart', async () => {
  const w = buildV5();
  const r = req(w, 'HOLD_CREATE', holdBody('mh-1'), ['k2-laptop']);
  ok(await w.submit(r));
  deny(await w.submit(r), 'ACTION_REPLAY');
  w.restartRoot();
  deny(await w.submit(r), 'ACTION_REPLAY');
});

test('P3/challenge: concurrent duplicate submissions -> exactly one accepted', async () => {
  const w = buildV5();
  const r = req(w, 'HOLD_CREATE', holdBody('mh-2'), ['k2-laptop']);
  const out = await Promise.all([w.submit(r), w.submit(r), w.submit(r)]);
  assert.equal(out.filter(x => x.ok).length, 1, JSON.stringify(out.map(x => x.ok || x.error.code)));
});

test('P3/challenge: one approval (one challenge) duplicated inside a request is refused (challenge probe or DUPLICATE_APPROVAL)', async () => {
  const w = buildV5();
  const r = req(w, 'HOLD_CREATE', { ...holdBody('mh-3'), class: 'CONFIRMED_OWNER_HOLD' }, ['k2-laptop']);
  // the F-V5-04 authentication probe consumes the challenge first (CHALLENGE_ALREADY_CONSUMED); without that, the handler's
  // approvalsArr refuses duplicate credIds (DUPLICATE_APPROVAL). Either way the request is refused and nothing changes.
  // For a passkey the WebAuthn sign counter is a third independent stop (WEBAUTHN_SIGNCOUNT_NOT_INCREASING).
  deny(await w.submit({ ...r, approvals: [r.approvals[0], r.approvals[0]] }), 'CHALLENGE_ALREADY_CONSUMED|DUPLICATE_APPROVAL|WEBAUTHN_SIGNCOUNT_NOT_INCREASING');
  assert.equal(w.root.state.v5.holds['mh-3'], undefined);
  // Ed25519 hardware key (no sign counter): one approval duplicated cannot stand in for a second signer either
  const r2 = req(w, 'HOLD_CREATE', { ...holdBody('mh-3b'), class: 'CONFIRMED_OWNER_HOLD' }, ['k3-root-hw']);
  deny(await w.submit({ ...r2, approvals: [r2.approvals[0], r2.approvals[0]] }), 'CHALLENGE_ALREADY_CONSUMED|DUPLICATE_APPROVAL');
  assert.equal(w.root.state.v5.holds['mh-3b'], undefined);
});

test('P3/challenge: a consumed challenge re-wrapped around a new action (new nonce) is refused', async () => {
  const w = buildV5();
  const r = req(w, 'HOLD_CREATE', holdBody('mh-4'), ['k2-laptop']);
  ok(await w.submit(r));
  const a2 = w.action('HOLD_CREATE', holdBody('mh-5'));
  deny(await w.submit({ action: a2, approvals: r.approvals }), 'CHALLENGE_NOT_FOR_THIS_ACTION|COMMAND_MISMATCH|ALREADY_CONSUMED');
});

test('P3/challenge layer isolation: with the action-nonce record removed from the state, the challenge alone refuses the replay', async () => {
  const w = buildV5();
  const r = req(w, 'HOLD_CREATE', holdBody('mh-6'), ['k2-laptop']);
  ok(await w.submit(r));
  const trs = w.root.chain(0); const tr = trs[trs.length - 1];
  const s = structuredClone(w.root.state);
  delete s.usedNonces[r.action.nonce]; // fixture: the ACTION_REPLAY layer is gone
  s.v5.holds = Object.fromEntries(Object.entries(s.v5.holds).filter(([k]) => k !== 'mh-6')); // and the hold id is free again
  const replay = { ...tr, seq: String(s.seq + 1), prev: s.head, at: new Date(w.now() + 1000).toISOString() };
  assert.throws(() => applyTransition(s, replay), (e) => e.code === 'CHALLENGE_ALREADY_CONSUMED' || /CHALLENGE_ALREADY_CONSUMED/.test(String(e.code) + e.message));
});

test('P3/rapid: suspending a scope credential ends the grant on the Root; its delayed payments are not accelerated and do not settle', async () => {
  const w = buildV5();
  await burst(w, 4);
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw'));
  ok(await w.cmd('SUSPEND', { credId: 'k1-phone', holdId: 'q1' }, ['k2-laptop']));
  deny(await rapidActivate(w), 'RAPID|CREDENTIAL|NOT_ACTIVE|PENDING');
  await w.advance(30 * MIN);
  assert.equal(w.vault.v5payments().filter(p => p.anomaly === 'RELEASED_BY_RAPID').length, 0);
  await w.advance(25 * H, 15 * MIN);
  assert.equal(w.vault.v5payments().filter(p => p.state === 'SETTLED').length, 0);
});

test('P3/rapid: an active grant whose scope credential is then suspended ends at that transition (no window for acceleration)', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  await burst(w, 3);
  ok(await w.cmd('SUSPEND', { credId: 'k1-phone', holdId: 'q2' }, ['k2-laptop']));
  assert.equal(w.root.state.v5.rapid.grants['rq-1'].status, 'ENDED_CREDENTIAL_RESTRICTED');
  assert.equal(w.vault.root.v5.rapid.grants['rq-1'].status, 'ENDED_CREDENTIAL_RESTRICTED', 'the vault replica applies the same post-transition rule');
  await w.advance(25 * H, 15 * MIN);
  assert.equal(w.vault.v5payments().filter(p => p.state === 'SETTLED').length, 0, 'k1 payments waiting in their buffer are cancelled at release (APPROVER_CREDENTIAL_NOT_ACTIVE)');
});

test('P3/rapid flow scope: a grant for k1 never accelerates k2 or a delegation; restart keeps the scope', async () => {
  const w = buildV5();
  await burst(w, 4, { credId: 'k2-laptop' });
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  w.restartVault();
  await w.advance(30 * MIN);
  assert.equal(w.vault.v5payments().filter(p => p.cred_id === 'k2-laptop' && p.anomaly === 'RELEASED_BY_RAPID').length, 0);
});

test('P3/rapid layer isolation: with the Root-side grant termination removed from the replica, the vault check alone refuses the grant', async () => {
  const w = buildV5();
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  const args = { credId: 'k1-phone', delegationId: null, recipient: 'merchant-a.mock', amount: Y(1), asset: 'NEAR' };
  assert.ok(w.vault.rapidGrantFor(args), 'grant applies while k1 is active');
  w.vault.root.creds['k1-phone'].status = 'suspended'; // fixture: grant still ACTIVE in the replica (normalizeRapid bypassed)
  assert.equal(w.vault.root.v5.rapid.grants['rq-1'].status, 'ACTIVE');
  assert.equal(w.vault.rapidGrantFor(args), null);
});
