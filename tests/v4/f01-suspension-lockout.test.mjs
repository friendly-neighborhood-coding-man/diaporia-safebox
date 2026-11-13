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
  for (const k of ['k1-phone', 'k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'].filter(k => !thief.includes(k))) ok(await act('SUSPEND', { credId: k }, [thief[0]]));
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

for (const thief of ['k1-phone', 'k4-freeze']) test(`F-V4-01 single stolen key (${thief}; campaign E shape for k4) suspends ALL four others => owner still recovers`, async () => {
  const w = buildV4();
  await lockout(w, [thief], (t, b, c) => w.legacyAct(t, b, c, { notIntended: true }));
  const r = await legitimateRecoveryV4(w, [thief]);
  assert.equal(r.outcome, 'RECOVERED', JSON.stringify(r));
  assert.ok(Object.entries(status(w)).every(([k, s]) => k === thief ? s !== 'active' : s === 'active'), JSON.stringify(status(w)));
  assert.equal(w.root.state.freeze.active, false);
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

// ---- review of 780e676 (freeze-reinforcement provenance): every FREEZE is its own hold; only holds placed solely by
// revoked keys are dropped; a supervisor breach freeze never lifts without its repair certificate; the owner sees it all.
const { buildSummary, renderText } = await import('../../src/v4/intent/summary.mjs');
const freeze = (w, id, creds) => w.legacyAct('FREEZE', { freezeId: id, reason: 'x', source: 'owner' }, creds, { notIntended: true });

test('F-V4-01b REINFORCEMENT: stolen K1 freezes, the owner deliberately reinforces with K2, recovery revokes K1 => vault stays frozen', async () => {
  const w = buildV4();
  ok(await freeze(w, 'fz-thief', ['k1-phone']));
  ok(await freeze(w, 'fz-owner', ['k2-laptop']));
  assert.equal(w.root.state.v4.freezeHolds.length, 2);
  let shown = null; const d0 = w.owner.decide; w.owner.decide = (sm, text, ctx) => { if (ctx.action.type === 'RECOVERY_CONSENT') shown = text; return d0(sm, text, ctx); };
  const r = await legitimateRecoveryV4(w, ['k1-phone']);
  assert.equal(r.outcome, 'RECOVERED', JSON.stringify(r));
  assert.match(shown, /drops freeze hold fz-thief \(placed only by k1-phone\)/);
  assert.match(shown, /Freeze fz-thief stays \(other holds: k2-laptop\)/);
  assert.equal(w.root.state.freeze.active, true, 'the K2 reinforcement keeps the vault frozen');
  assert.deepEqual(w.root.state.v4.freezeHolds.map(h => h.by.join('+')), ['k2-laptop']);
  ok(await w.ownerAct('UNFREEZE', { freezeId: w.root.state.freeze.freezeId }, ['k2-laptop', 'k3-root-hw']));
  assert.equal(w.root.state.freeze.active, false);
});

test('F-V4-01b SUPERVISOR: a breach freeze reinforced by the stolen key is never lifted by recovery', async () => {
  for (const order of ['supervisor-first', 'thief-first']) {
    const w = buildV4();
    const sup = () => w.submitRaw('FREEZE', { freezeId: 'sup-1', reason: 'verifier: unauthorized effect', source: 'supervisor' }, { attest: (a) => ({ supervisorSig: w.owner.supervisorFreezeSign(a) }), intended: false });
    if (order === 'supervisor-first') { ok(await sup()); ok(await freeze(w, 'fz-thief', ['k1-phone'])); }
    else { ok(await freeze(w, 'fz-thief', ['k1-phone'])); ok(await sup()); }
    const r = await legitimateRecoveryV4(w, ['k1-phone']);
    assert.equal(r.outcome, 'RECOVERED', order + JSON.stringify(r));
    assert.equal(w.root.state.freeze.active, true, order);
    assert.equal(w.root.state.freeze.requiresRepair, true, order);
  }
  // defence in depth: even if the supervisor's own hold record were missing, requiresRepair alone keeps the freeze
  const w = buildV4();
  ok(await w.submitRaw('FREEZE', { freezeId: 'sup-1', reason: 'verifier: unauthorized effect', source: 'supervisor' }, { attest: (a) => ({ supervisorSig: w.owner.supervisorFreezeSign(a) }), intended: false }));
  ok(await freeze(w, 'fz-thief', ['k1-phone']));
  w.root.state.v4.freezeHolds = w.root.state.v4.freezeHolds.filter(h => !h.by[0].startsWith('source:'));
  assert.equal((await legitimateRecoveryV4(w, ['k1-phone'])).outcome, 'RECOVERED');
  assert.equal(w.root.state.freeze.active, true);
});

test('F-V4-01b HONEST OWNER FREEZE: a freeze placed with a key that is later rotated stays; one placed with a key later lost is shown before it is dropped', async () => {
  // rotation (not recovery) never touches freeze holds
  const w = buildV4();
  ok(await freeze(w, 'fz-own', ['k1-phone']));
  const { Device, ACCOUNT } = await import('../../src/v4/kit.mjs');
  const a = w.owner.action(w.view(), 'ROTATE', { credId: 'k4-freeze', newCredential: null });
  const d = new Device({ credId: 'k4-freeze-2', role: 'FREEZE', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' }); w.owner.devices.push(d);
  a.body.newCredential = d.enrollment(ACCOUNT, `${ACCOUNT}:${a.nonce}`);
  const rr = await w.submit({ action: a, approvals: w.owner.authorize(w.root.state, a, ['k3-root-hw', 'k4-freeze']) });
  assert.equal(w.root.state.freeze.active, true, 'freeze survives a rotation: ' + JSON.stringify(rr.error ?? rr.ok));
  // the owner froze with K1, then K1 is lost: the consent screen names the hold the recovery would drop, so the owner
  // can decline (the case then does not complete and the freeze stays) or approve and re-freeze with one tap afterwards
  const w2 = buildV4();
  ok(await freeze(w2, 'fz-own', ['k1-phone']));
  w2.owner.decide = (sm, text, ctx) => !(ctx.action.type === 'RECOVERY_CONSENT' && /drops freeze hold fz-own/.test(text));
  const r2 = await legitimateRecoveryV4(w2, ['k1-phone']);
  assert.notEqual(r2.outcome, 'RECOVERED');
  assert.equal(w2.root.state.freeze.active, true, 'declined => intent preserved');
  const w3 = buildV4();
  ok(await freeze(w3, 'fz-own', ['k1-phone']));
  assert.equal((await legitimateRecoveryV4(w3, ['k1-phone'])).outcome, 'RECOVERED');
  assert.equal(w3.root.state.freeze.active, false);
  ok(await freeze(w3, 'fz-again', ['k2-laptop']));
  assert.equal(w3.root.state.freeze.active, true, 're-freeze with one tap');
});
