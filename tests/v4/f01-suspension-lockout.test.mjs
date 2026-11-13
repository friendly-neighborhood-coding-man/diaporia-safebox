// F-V4-01 (campaign B_r3, 2026-11-13T1912-B_r3-A-original): stolen DAILY keys suspend every other owner key (SUSPEND is
// a one-signature protective action) and freeze the vault. Inherited from V3: a suspended survivor's consent never
// counted toward recovery, so the owner could not recover. Repair: a suspended survivor's own intent-bound consent counts,
// and a completed recovery lifts the suspensions / owner-source freeze imposed only by the credentials it revokes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { legitimateRecovery } from '../../src/v3/recovery/sim.mjs';
import { buildV4 } from '../../src/v4/world.mjs';
import { legitimateRecoveryV4, openCaseV4, evidence4 as E } from '../../src/v4/recovery/sim.mjs';
import { H, ok, deny } from './helpers.mjs';

const status = (w) => Object.fromEntries(Object.values(w.root.state.creds).map(c => [c.credId, c.status]));
async function lockout(w, thief, act) {
  ok(await act('FREEZE', { freezeId: 'fz-1', reason: 'x', source: 'owner' }, thief));
  for (const k of ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'].filter(k => !thief.includes(k))) ok(await act('SUSPEND', { credId: k }, [thief[0]]));
}

test('F-V4-01 BASELINE: on V3 one stolen key suspends the others and the owner can no longer recover', async () => {
  const w = buildV3();
  const act = (t, b, c) => w.admin.request('SUBMIT', { request: (() => { const a = w.owner.action(w.view(), t, b); return { action: a, approvals: w.owner.approvals(a, c) }; })() });
  await lockout(w, ['k1-phone'], act);
  const r = await legitimateRecovery(w, ['k1-phone']);
  assert.match(r.outcome, /FAILED|QUORUM/, JSON.stringify(r));
});

test('F-V4-01 REPLAY (campaign B shape): two stolen DAILY keys freeze + suspend k3/k4/k5 => owner recovers, suspensions and freeze lifted', async () => {
  const w = buildV4();
  const act = (t, b, c) => w.legacyAct(t, b, c, { notIntended: true });
  await lockout(w, ['k1-phone', 'k2-laptop'], act);
  assert.deepEqual([w.root.state.freeze.active, status(w)['k3-root-hw'], status(w)['k5-recovery-hw']], [true, 'suspended', 'suspended']);
  const r = await legitimateRecoveryV4(w, ['k1-phone', 'k2-laptop']);
  assert.equal(r.outcome, 'RECOVERED', JSON.stringify(r));
  const st = status(w);
  for (const k of ['k3-root-hw', 'k4-freeze', 'k5-recovery-hw']) assert.equal(st[k], 'active', k);
  assert.equal(w.root.state.freeze.active, false);
  assert.equal((await w.verify()).authority.unauthorized.length, 0);
});

test('F-V4-01 single stolen key suspends ALL four others => owner still recovers', async () => {
  const w = buildV4();
  await lockout(w, ['k1-phone'], (t, b, c) => w.legacyAct(t, b, c, { notIntended: true }));
  const r = await legitimateRecoveryV4(w, ['k1-phone']);
  assert.equal(r.outcome, 'RECOVERED', JSON.stringify(r));
  assert.ok(Object.entries(status(w)).every(([k, s]) => k === 'k1-phone' ? s !== 'active' : s === 'active'), JSON.stringify(status(w)));
});

test('F-V4-01 narrowness: owner-imposed suspensions survive; a suspended key consent is intent-bound; an attacker case still cannot complete', async () => {
  const w = buildV4();
  // the owner suspends K4 with K2 (not lost) and the thief suspends K3 with K1
  ok(await w.legacyAct('SUSPEND', { credId: 'k4-freeze' }, ['k2-laptop'], { notIntended: true }));
  ok(await w.legacyAct('SUSPEND', { credId: 'k3-root-hw' }, ['k1-phone'], { notIntended: true }));
  // a V3-style (action-digest) consent from the suspended survivor is refused
  ok((await openCaseV4(w, { lost: ['k1-phone'] })).r); ok(await E.identity(w, 'idv-1'));
  deny(await w.submitRaw('RECOVERY_CONSENT', { caseId: w.root.state.case.caseId, caseDigest: w.root.state.case.digest }, { approvals: (a) => w.owner.approvals(a, ['k3-root-hw']), intended: false }), 'AUTHORIZATION_INTENT_REQUIRED');
  ok(await E.orcCancel(w)); await w.advance(13 * H, H);
  const r = await legitimateRecoveryV4(w, ['k1-phone']);
  assert.equal(r.outcome, 'RECOVERED', JSON.stringify(r));
  assert.equal(status(w)['k3-root-hw'], 'active', 'thief-imposed suspension lifted');
  assert.equal(status(w)['k4-freeze'], 'suspended', 'owner-imposed suspension kept');
  // an attacker-opened minority case with suspended survivors still needs every survivor's consent
  const w2 = buildV4();
  ok(await w2.legacyAct('SUSPEND', { credId: 'k3-root-hw' }, ['k1-phone'], { notIntended: true }));
  ok((await openCaseV4(w2, { lost: ['k2-laptop'], attacker: true })).r); ok(await E.identity(w2, 'idv-1'));
  ok(await E.consent(w2, 'k1-phone'));
  await w2.advance(73 * H, H);
  const c = await w2.recovery.tryComplete(w2.root.state);
  assert.notEqual(c.ok, true);
  assert.equal((await w2.verify()).authority.unauthorized.length, 0);
});
