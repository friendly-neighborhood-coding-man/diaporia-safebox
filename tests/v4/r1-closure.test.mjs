// R-1 closure: silence, acknowledgements, elapsed time and collusion of every independent party never authorize a
// reconstitution. Only the owner's pre-enrolled Owner Recovery Credential (ORC), bound to the exact case digest, does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { ownerOpenCase, evidence as E3 } from '../../src/v3/recovery/sim.mjs';
import { buildV4 } from '../../src/v4/world.mjs';
import { openCaseV4, evidence4 as E, legitimateRecoveryV4 } from '../../src/v4/recovery/sim.mjs';
import { H, D, Y, ok, deny, cs, last } from './helpers.mjs';

const MAJ = ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'];

/** The V3 R-1 collusion: stolen K1 + all guardians + both IDVs + channel acks + 72 h owner silence. */
async function r1Attack(w, { acks = ['ch-email', 'ch-postal'], wait = 73 * H } = {}) {
  const o = await openCaseV4(w, { lost: MAJ, full: true, attacker: true }); ok(o.r); w._attackDevices = o.devices;
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  ok(await E.consent(w, 'k1-phone'));
  for (const g of ['g1', 'g2', 'g3']) ok(await E.guardian(w, g));
  await w.advance(wait, H);
  for (const ch of acks) ok(await E.ack(w, ch, 'NO_OBJECTION', { intended: false }));
}

test('BASELINE: V3 R-1 reproduces (takeover) on the unchanged V3 code', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: MAJ, full: true, attacker: true })).r);
  ok(await E3.identity(w, 'idv-1')); ok(await E3.identity(w, 'idv-2'));
  ok(await E3.consent(w, 'k1-phone'));
  for (const g of ['g1', 'g2', 'g3']) ok(await E3.guardian(w, g));
  await w.advance(73 * H, H);
  ok(await E3.ack(w, 'ch-email')); ok(await E3.ack(w, 'ch-postal'));
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  assert.equal(r.ok, true);
  assert.equal((await w.verify()).takeovers.length, 1);
});

test('R-1 CLOSED: same collusion on V4 => RECONSTITUTE denied (OWNER_AUTHORIZATION_REQUIRED), case expires, no authority transfer', async () => {
  const w = buildV4();
  const epoch0 = w.root.state.epoch, creds0 = JSON.stringify(Object.keys(w.root.state.creds).sort());
  await r1Attack(w);
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  deny(r, 'OWNER_AUTHORIZATION_REQUIRED');
  ok(await E.expire(w));
  assert.equal(cs(w), null); assert.equal(last(w).outcome, 'EXPIRED_UNAPPROVED');
  assert.equal(w.root.state.epoch, epoch0); assert.equal(JSON.stringify(Object.keys(w.root.state.creds).sort()), creds0);
  assert.equal(w.root.state.lockdown.active, false, 'lockdown released at expiry');
  const v = await w.verify(); assert.equal(v.chainValid, true); assert.equal(v.takeovers.length, 0); assert.deepEqual(v.authority.unauthorized, []);
  // the owner's untouched devices still pay
  ok(await w.pay({ amountYocto: Y(1) }));
});

test('R-1 variant: acknowledgements from EVERY channel + arbitrarily long silence still never authorize', async () => {
  const w = buildV4();
  await r1Attack(w, { acks: ['ch-phone', 'ch-email', 'ch-postal'], wait: 72 * H + 6 * D });
  deny(await w.recovery.tryComplete(w.root.state), 'OWNER_AUTHORIZATION_REQUIRED|RECOVERY_CASE_EXPIRED');
  assert.equal((await w.verify()).takeovers.length, 0);
});

test('R-1 variant: attacker tries to supply owner authorization with stolen K1, a guardian key, a forged ORC id, or a self-made ORC', async () => {
  const w = buildV4();
  await r1Attack(w, { wait: 2 * H, acks: [] });
  // K1 is not an ORC
  deny(await w.submitRaw('RECOVERY_OWNER_AUTHORIZE', { caseId: cs(w).caseId, caseDigest: cs(w).digest, orcId: 'k1-phone' }, { approvals: (a) => w.owner.authorize(w.root.state, a, ['k1-phone']), intended: false }), 'ORC_UNKNOWN|OWNER_AUTHORIZATION_ONE_ORC');
  // unknown ORC id
  deny(await w.submitRaw('RECOVERY_OWNER_AUTHORIZE', { caseId: cs(w).caseId, caseDigest: cs(w).digest, orcId: 'orc-9' }, { approvals: (a) => [{ credId: 'orc-9', intent: {}, grant: {}, sig: 'x' }], intended: false }), 'ORC_UNKNOWN');
  // a self-made key presented as orc-1 (attacker does not hold the ORC): signature over the right intent with the wrong key
  const { newEdSigner } = await import('../../src/v3/common/canon.mjs');
  const real = w.owner.orcs['orc-1']; w.owner.orcs['orc-1'] = newEdSigner('evil-orc');
  deny(await E.orcAuthorize(w), 'APPROVAL_BAD_SIGNATURE');
  w.owner.orcs['orc-1'] = real;
  // guardians + attestation mixed into the authorization are refused
  deny(await w.submitRaw('RECOVERY_OWNER_AUTHORIZE', { caseId: cs(w).caseId, caseDigest: cs(w).digest, orcId: 'orc-1' }, { approvals: (a) => w.owner.authorize(w.root.state, a, ['orc-1']), guardians: ['g1'], intended: false }), 'MIXED_EVIDENCE');
  assert.equal(cs(w).v4.ownerAuth, null);
});

test('R-1 variant: an ORC authorization is bound to the exact case digest (replan / other case / replay all invalidate it)', async () => {
  const w = buildV4();
  const o = await openCaseV4(w, { lost: MAJ, full: true });
  ok(o.r); ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  // capture an authorization for THIS digest, then make the case digest change through a replan
  const a1 = w.owner.action(w.view(), 'RECOVERY_OWNER_AUTHORIZE', { caseId: cs(w).caseId, caseDigest: cs(w).digest, orcId: 'orc-1' });
  const ap1 = w.owner.authorize(w.root.state, a1, ['orc-1']);
  ok(await w.submit({ action: a1, approvals: ap1 }));
  assert.equal(cs(w).v4.ownerAuth.caseDigest, cs(w).digest);
  // replay of the exact same submission: nonce + challenge consumed
  deny(await w.submit({ action: a1, approvals: ap1 }), 'NONCE|CHALLENGE_ALREADY_CONSUMED|REPLAY');
  // stale digest (from a different case) is refused
  deny(await w.submitRaw('RECOVERY_OWNER_AUTHORIZE', { caseId: cs(w).caseId, caseDigest: '0'.repeat(64), orcId: 'orc-1' }, { approvals: (a) => w.owner.authorize(w.root.state, a, ['orc-1']) }), 'RECOVERY_CASE_MISMATCH');
});

test('R-1: an ORC alone is not a master key (no guardians / identity evidence => no reconstitution)', async () => {
  const w = buildV4();
  ok((await openCaseV4(w, { lost: MAJ, full: true })).r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  ok(await E.orcAuthorize(w));
  await w.advance(73 * H, H);
  const r = await w.recovery.tryComplete(w.root.state);
  deny(r, 'GUARDIAN|EVIDENCE|QUORUM|CONSENT|ACK');
  assert.equal((await w.verify()).takeovers.length, 0);
});

test('R-1: ORC is never a payment, Purpose or budget authority', async () => {
  const w = buildV4();
  await assert.rejects(async () => { const r = await w.pay({ credId: 'orc-1', amountYocto: Y(1) }); if (!r.ok) throw new Error(r.error.code); });
  deny(await w.ownerAct('AMEND_PURPOSE', { purpose: { ...w.root.state.purpose, version: String(Number(w.root.state.purpose.version) + 1) } }, ['orc-1', 'k3-root-hw'], { notIntended: true }), '');
  deny(await w.ownerAct('UNFREEZE', { freezeId: 'x' }, ['orc-1'], { notIntended: true }), '');
});

test('GENUINE OWNER: majority loss (K2..K5) succeeds with the ORC; minority loss succeeds without it', async () => {
  let w = buildV4();
  const rep = await legitimateRecoveryV4(w, MAJ);
  assert.equal(rep.outcome, 'NEW_EPOCH', JSON.stringify(rep));
  const v = await w.verify(); assert.equal(v.chainValid, true); assert.equal(v.takeovers.length, 0); assert.equal(v.authority.unauthorized.length, 0);
  const daily = Object.values(w.root.state.creds).find(c => c.status === 'active' && c.role === 'DAILY');
  ok(await w.pay({ credId: daily.credId, amountYocto: Y(1) }));
  w = buildV4();
  const rep2 = await legitimateRecoveryV4(w, ['k2-laptop'], { orc: null });
  assert.equal(rep2.outcome, 'RECOVERED', JSON.stringify(rep2));
});

test('GENUINE OWNER without ORC (lost too): majority loss is not recoverable by the recovery path and expires safely', async () => {
  const w = buildV4(); w.owner.lostOrcs.add('orc-1');
  const rep = await legitimateRecoveryV4(w, MAJ);
  assert.match(rep.outcome, /FAILED:OWNER_AUTHORIZATION_REQUIRED/);
  assert.equal(rep.closedAs, 'EXPIRED_UNAPPROVED');
  assert.equal((await w.verify()).takeovers.length, 0);
});

test('REATTEMPT COOLDOWN: 12 h per subject holder, not per case id; fresh nonce + fresh plan keys required', async () => {
  const w = buildV4();
  await r1Attack(w);
  ok(await E.expire(w));
  const burned = Object.keys(w.root.state.v4.burnedPlanKeys).length; assert.ok(burned >= 4);
  // a new case id 1 minute later is refused
  deny((await openCaseV4(w, { lost: MAJ, full: true, attacker: true, caseId: 'totally-new-id' })).r, 'RECOVERY_REATTEMPT_COOLDOWN');
  await w.advance(12 * H, H);
  // reusing a rejected plan key is refused even after the cooldown
  deny((await openCaseV4(w, { lost: MAJ, full: true, attacker: true, planDevices: w._attackDevices, planMeta: false })).r, 'PLAN_KEY_PREVIOUSLY_REJECTED');
  // a fresh plan after the cooldown is accepted (and will again need ORC authorization)
  const r2 = await openCaseV4(w, { lost: MAJ, full: true, attacker: true });
  ok(r2.r);
});

test('CLAIM BUDGET + LOCKDOWN BUDGET: repeated false claims cannot lock the owner out indefinitely', async () => {
  const w = buildV4();
  for (let i = 0; i < 3; i++) {
    ok((await openCaseV4(w, { lost: MAJ, full: true, attacker: true })).r);
    ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
    await w.advance(73 * H, H); ok(await E.expire(w));
    await w.advance(12 * H + 60_000, H);
  }
  const used = w.root.state.v4.lockdowns.reduce((t, l) => t + (l.end - l.start), 0);
  assert.ok(used <= 96 * H + 73 * H, 'lockdown time bounded by the 96 h budget (+ the one case that crossed it)');
  assert.ok(w.root.state.v4.lockdowns.length <= 2, 'the third claim ran without a lockdown');
  deny((await openCaseV4(w, { lost: MAJ, full: true, attacker: true })).r, 'RECOVERY_CLAIM_BUDGET_EXHAUSTED');
  // the genuine owner with the ORC can still open an attested case
  const r = await openCaseV4(w, { lost: MAJ, full: true, orcAttest: 'orc-1' });
  ok(r.r); assert.equal(cs(w).v4.ownerAttested, true);
});

test('CANCELLATION: the ORC cancels a fraudulent case at once and releases the lockdown', async () => {
  const w = buildV4();
  ok((await openCaseV4(w, { lost: MAJ, full: true, attacker: true })).r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  assert.equal(w.root.state.lockdown.active, true);
  ok(await E.orcCancel(w));
  assert.equal(cs(w), null); assert.equal(last(w).outcome, 'CANCELLED'); assert.equal(w.root.state.lockdown.active, false);
  ok(await w.pay({ amountYocto: Y(1) }));
});

test('EXPIRY: takes no evidence, is refused before the deadline, and a HOLD (objection) is bounded by the same deadline', async () => {
  const w = buildV4();
  ok((await openCaseV4(w, { lost: ['k2-laptop'] })).r);
  ok(await E.identity(w, 'idv-1'));
  deny(await E.expire(w), 'RECOVERY_NOT_EXPIRED');
  ok(await E.object(w, 'k3-root-hw'));
  await w.advance(73 * H, H);
  ok(await E.expire(w));
  assert.equal(last(w).outcome, 'EXPIRED_UNAPPROVED');
});
