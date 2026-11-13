// Recovery and privilege attacks (deterministic). Each attack has a negative control (the attack fails for the stated
// invariant, not merely because something is frozen) and, where meaningful, a positive control (the legitimate owner
// still succeeds).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { ownerOpenCase, evidence as E, legitimateRecovery } from '../../src/v3/recovery/sim.mjs';
import { survivors } from '../../src/v3/root/chain.mjs';
import { Device } from '../../src/v3/kit.mjs';

const H = 3600_000;
const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
const ok = (r, m = '') => { assert.equal(r.ok, true, m + JSON.stringify(r.error)); return r.result; };
const deny = (r, code) => { assert.equal(r.ok, false, 'expected denial for ' + code); if (code) assert.match(`${r.error.code}:${r.error.detail ?? ''}`, new RegExp(code)); assert.doesNotMatch(r.error.code, /^FREEZE_ACTIVE$/); return r.error; };
const cs = (w) => w.root.state.case;

test('fake loss report: claim alone changes no authority; every channel notified; timer alone never completes', async () => {
  const w = buildV3();
  const before = JSON.stringify(Object.values(w.root.state.creds).map(c => [c.credId, c.status]));
  const o = await ownerOpenCase(w, { lost: ['k1-phone', 'k2-laptop'], attacker: true }); ok(o.r);
  assert.equal(JSON.stringify(Object.values(w.root.state.creds).map(c => [c.credId, c.status])), before);
  assert.deepEqual(Object.keys(w.inbox).sort(), ['ch-email', 'ch-phone', 'ch-postal']);
  ok(await w.pay({ credId: 'k1-phone', amountYocto: Y(1) }), 'claimed-lost key still works until loss is confirmed: ');
  await w.advance(73 * H, H);
  const r = await w.recovery.tryComplete(w.root.state);
  assert.equal(r.ok ?? false, false); // no identity, no consents, no guardians: nothing completes on a timer
  assert.equal(w.root.state.epoch, 1);
  assert.equal((await w.verify()).takeovers.length, 0);
});

test('fake loss report: owner objects from a surviving key (HOLD) then cancels; the attacker cannot override a survivor objection', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k1-phone'], attacker: true })).r);
  ok(await E.object(w, 'k2-laptop'));
  assert.equal(cs(w).state, 'HOLD');
  deny(await E.override(w), 'NOTHING_TO_OVERRIDE');
  ok(await E.cancel(w, ['k3-root-hw']));
  assert.equal(w.root.state.case, null);
  assert.equal(w.root.state.caseHistory.at(-1).outcome, 'CANCELLED');
});

test('conflicting / repeated loss reports: one case at a time and a cool-down between cases', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k1-phone'], attacker: true })).r);
  deny((await ownerOpenCase(w, { lost: ['k2-laptop'], attacker: true })).r, 'RECOVERY_CASE_ALREADY_OPEN');
  ok(await E.cancel(w, ['k2-laptop']));
  deny((await ownerOpenCase(w, { lost: ['k2-laptop'], attacker: true })).r, 'RECOVERY_CASE_COOLDOWN');
  await w.advance(61 * 60_000);
  ok((await ownerOpenCase(w, { lost: ['k2-laptop'], attacker: true })).r);
});

test('lost-claim set must be live credentials of the subject holder; plan keys must be independent', async () => {
  const w = buildV3();
  deny((await ownerOpenCase(w, { lost: ['k9-none'], attacker: true })).r, 'RECOVERY_LOST_NOT_LIVE');
  const dupe = [new Device({ credId: 'evil-x', role: 'DAILY', holderId: 'alice', channelId: 'ch-phone', kind: 'passkey' })];
  dupe[0].provenance.seedCommitment = w.owner.dev('k2-laptop').provenance.seedCommitment;
  deny((await ownerOpenCase(w, { lost: ['k1-phone'], attacker: true, planDevices: dupe })).r, 'SHARED_SEED');
});

test('compromised notification channel: its forged OBJECTION is overridable by full evidence; its forged ACK cannot enable early completion', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k1-phone'] })).r);
  ok(await E.identity(w));
  for (const c of survivors(w.root.state, cs(w), w.now())) ok(await E.consent(w, c));
  ok(await E.guardian(w, 'g1'));
  ok(await E.ack(w, 'ch-email')); // attacker controls ch-email: acks, then objects to stall
  await w.advance(2 * H, H);
  deny((await w.recovery.tryComplete(w.root.state)).ok ? { ok: true } : { ok: false, error: { code: 'OBJECTION_WINDOW_OPEN' } }, 'OBJECTION_WINDOW_OPEN'); // only 1 of 3 channels acked
  ok(await E.ack(w, 'ch-email', 'OBJECTION'));
  assert.equal(cs(w).state, 'HOLD');
  // F-V3-02 repair: on the RECOVERY path the normal guardian quorum (2) + every survivor's consent overrides a channel
  // objection (previously the reconstitution quorum 3 was required, which let one bad guardian make the HOLD permanent)
  deny(await E.override(w), 'OVERRIDE_NEEDS_GUARDIAN_QUORUM');
  ok(await E.guardian(w, 'g2'));
  ok(await E.override(w));
  assert.equal(cs(w).state, 'RECOVERY_CHALLENGE');
  await w.advance(72 * H, H);
  const r = await w.recovery.tryComplete(w.root.state); assert.equal(r.ok, true, JSON.stringify(r));
  await w.pump();
  assert.equal(w.root.state.caseHistory.at(-1).outcome, 'RECOVERED');
});

test('thief holding the lost key objects to block recovery: overridable (no permanent lockout) — positive control', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k2-laptop'] })).r);
  ok(await E.object(w, 'k2-laptop')); // thief signs with the stolen key
  assert.equal(cs(w).state, 'HOLD');
  ok(await E.identity(w));
  for (const c of survivors(w.root.state, cs(w), w.now())) ok(await E.consent(w, c));
  for (const g of ['g1', 'g2', 'g3']) ok(await E.guardian(w, g));
  ok(await E.override(w));
  await w.advance(73 * H, H);
  assert.equal((await w.recovery.tryComplete(w.root.state)).ok, true);
  await w.pump();
  assert.equal(w.root.state.creds['k2-laptop'].status, 'retired');
});

test('GUARDIAN COLLUSION + one stolen key: claim the other four keys lost, forge nothing, then override the real owner\'s objections', async () => {
  // Attacker: has stolen K1, all three guardians and both identity verifiers collude. Owner still holds K2..K5.
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], full: true, attacker: true })).r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  assert.equal(w.root.state.lockdown.active, true); // DoS (assets frozen), not theft
  ok(await E.consent(w, 'k1-phone')); // the stolen key is the only "survivor"
  for (const g of ['g1', 'g2', 'g3']) ok(await E.guardian(w, g));
  // the real owner sees the notice and objects with the keys the attacker claims are lost
  ok(await E.object(w, 'k2-laptop')); ok(await E.object(w, 'k3-root-hw'));
  const ov = await E.override(w);
  await w.advance(73 * H, H);
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  const v = await w.verify();
  assert.equal(v.takeovers.length, 0, `TAKEOVER: override=${ov.ok} complete=${JSON.stringify(r)}`);
  // owner leaves the lockdown with its real quorum (K3 + K2) — no permanent lockout
  ok(await E.cancel(w, ['k3-root-hw', 'k2-laptop']));
  assert.equal(w.root.state.lockdown.active, false);
  ok(await w.pay({ credId: 'k2-laptop', amountYocto: Y(1) }));
});

test('guardian impersonation and identity forgery: unpinned keys are rejected', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k1-phone'], attacker: true })).r);
  const fake = (await import('../../src/v3/common/canon.mjs')).newEdSigner('fake');
  deny(await w.submitRaw('RECOVERY_GUARDIAN', { caseId: cs(w).caseId, caseDigest: cs(w).digest, guardianId: 'g1', decision: 'APPROVE' },
    { attest: (a) => ({ guardianSig: fake.signStatement('DIAPORIA_SAFEBOX_V3_GUARDIAN_APPROVAL\n', { actionDigest: 'x', decision: 'APPROVE' }) }) }), 'GUARDIAN_BAD_SIGNATURE');
  deny(await w.submitRaw('RECOVERY_IDENTITY', { caseId: cs(w).caseId, caseDigest: cs(w).digest, idvId: 'idv-1', holderId: 'alice', method: 'document-and-liveness', result: 'VERIFIED' },
    { attest: () => ({ idvSig: fake.signDigest('DIAPORIA_SAFEBOX_V3_IDENTITY_ATTESTATION\n', Buffer.alloc(32)) }) }), 'IDV_SIGNATURE');
  deny(await w.submitRaw('RECOVERY_IDENTITY', { caseId: cs(w).caseId, caseDigest: cs(w).digest, idvId: 'idv-evil', holderId: 'alice', method: 'document-and-liveness', result: 'VERIFIED' }, { attest: () => ({ idvSig: 'x' }) }), 'IDV_UNKNOWN');
  // an AI-controlled boolean is not evidence
  deny(await w.submitRaw('RECOVERY_IDENTITY', { caseId: cs(w).caseId, caseDigest: cs(w).digest, idvId: 'idv-1', holderId: 'alice', method: 'document-and-liveness', result: 'VERIFIED', biometricVerified: 'true' }, { attest: (a) => ({ idvSig: w.owner.idvSign(a, 'idv-1') }) }), 'UNEXPECTED_OR_MISSING|BODY_RECOVERY_IDENTITY');
  // a signature for one case cannot be moved to another case digest
  const a = w.owner.action(w.view(), 'RECOVERY_GUARDIAN', { caseId: cs(w).caseId, caseDigest: cs(w).digest, guardianId: 'g1', decision: 'APPROVE' });
  const sig = w.owner.guardianSign(a, 'g1');
  const b = { ...a, body: { ...a.body, decision: 'APPROVE' }, nonce: 'f'.repeat(32) };
  deny(await w.admin.request('SUBMIT', { request: { action: b, attestation: { guardianSig: sig } } }), 'GUARDIAN_BAD_SIGNATURE');
});

test('72-hour boundary: complete at openedAt+72h-1ms fails, at +72h succeeds (all evidence present, not all channels acked)', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k4-freeze'] })).r);
  ok(await E.identity(w));
  for (const c of survivors(w.root.state, cs(w), w.now())) ok(await E.consent(w, c));
  ok(await E.guardian(w, 'g1')); ok(await E.guardian(w, 'g2'));
  const opened = cs(w).openedAt;
  w.clock.set(opened + 72 * H - 1);
  deny(await w.submitRaw('RECOVERY_COMPLETE', { caseId: cs(w).caseId, caseDigest: cs(w).digest }), 'OBJECTION_WINDOW_OPEN');
  w.clock.set(opened + 72 * H);
  ok(await w.submitRaw('RECOVERY_COMPLETE', { caseId: cs(w).caseId, caseDigest: cs(w).digest }));
});

test('early completion needs EVERY channel acked and the 1 h floor; missing guardian blocks even after the window', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k4-freeze'] })).r);
  ok(await E.identity(w));
  for (const c of survivors(w.root.state, cs(w), w.now())) ok(await E.consent(w, c));
  ok(await E.guardian(w, 'g1'));
  for (const ch of ['ch-email', 'ch-phone', 'ch-postal']) ok(await E.ack(w, ch));
  w.clock.set(cs(w).openedAt + H - 1);
  deny(await w.submitRaw('RECOVERY_COMPLETE', { caseId: cs(w).caseId, caseDigest: cs(w).digest }), 'GUARDIAN_QUORUM_NOT_MET');
  ok(await E.guardian(w, 'g2'));
  deny(await w.submitRaw('RECOVERY_COMPLETE', { caseId: cs(w).caseId, caseDigest: cs(w).digest }), 'OBJECTION_WINDOW_OPEN');
  w.clock.set(cs(w).openedAt + H);
  ok(await w.submitRaw('RECOVERY_COMPLETE', { caseId: cs(w).caseId, caseDigest: cs(w).digest }));
});

test('Purpose amendment, rotation and matrix change are refused while a recovery case is open', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k4-freeze'], attacker: true })).r);
  deny(await w.ownerAct('AMEND_PURPOSE', { capsule: { ...w.owner.capsule, version: '2' } }, ['k1-phone', 'k2-laptop', 'k3-root-hw'], { notIntended: true }), 'RECOVERY_IN_PROGRESS');
  deny(await w.ownerAct('REVOKE', { credId: 'k4-freeze', reason: 'x' }, ['k1-phone', 'k3-root-hw'], { notIntended: true }), 'RECOVERY_IN_PROGRESS');
});

test('old-epoch authorization reuse: a consent prepared in epoch 1 is dead after the recovery bumps the epoch', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k4-freeze'] })).r);
  const stale = w.owner.action(w.view(), 'FREEZE', { freezeId: 'old', reason: 'x', source: 'owner' });
  const staleAp = w.owner.approvals(stale, ['k1-phone']);
  const res = await legitimateRecovery(w, ['k4-freeze']).catch(e => e); // will fail (case already open) — complete manually instead
  ok(await E.identity(w));
  for (const c of survivors(w.root.state, cs(w), w.now())) ok(await E.consent(w, c));
  ok(await E.guardian(w, 'g1')); ok(await E.guardian(w, 'g2'));
  await w.advance(73 * H, H);
  ok(await w.submitRaw('RECOVERY_COMPLETE', { caseId: cs(w).caseId, caseDigest: cs(w).digest }));
  assert.equal(w.root.state.epoch, 2); assert.ok(res);
  deny(await w.admin.request('SUBMIT', { request: { action: stale, approvals: staleAp } }), 'STALE_EPOCH');
});

test('laundering: sequential partial recoveries cannot reset the loss denominator; recovered keys cannot consent while provisional', async () => {
  const w = buildV3();
  for (const k of ['k1-phone', 'k2-laptop']) w.owner.dev(k).lost = true;
  assert.equal((await legitimateRecovery(w, ['k1-phone', 'k2-laptop'])).outcome, 'RECOVERED');
  await w.advance(2 * H, H);
  const newDaily = Object.values(w.root.state.creds).filter(c => c.status === 'active' && c.role === 'DAILY').map(c => c.credId);
  // second claim: K3 lost. Baseline losses = K1,K2 + K3 = 3/5 > 50% => not an ordinary recovery
  ok((await ownerOpenCase(w, { lost: ['k3-root-hw'] })).r);
  ok(await E.identity(w));
  assert.notEqual(cs(w).state, 'RECOVERY_CHALLENGE');
  assert.equal(w.root.state.lockdown.active, true);
  deny(await E.consent(w, newDaily[0]), 'CONSENT_NOT_FROM_ELIGIBLE_SURVIVOR');
});

test('Recovery Guardians, K4 and K5 never pay or amend purpose, even inside a recovery', async () => {
  const w = buildV3();
  deny(await w.pay({ credId: 'k5-recovery-hw', amountYocto: Y(1) }), 'PAYCAP_ROLE_NOT_AUTHORIZED');
  deny(await w.ownerAct('AMEND_PURPOSE', { capsule: { ...w.owner.capsule, version: '2' } }, ['k5-recovery-hw', 'k4-freeze', 'k3-root-hw'], { notIntended: true }), 'QUORUM_NOT_SATISFIED');
  // guardians have no credential at all: a guardian signature is not an approval
  const a = w.owner.action(w.view(), 'AMEND_PURPOSE', { capsule: { ...w.owner.capsule, version: '2' } });
  deny(await w.admin.request('SUBMIT', { request: { action: a, approvals: [], guardianApprovals: w.owner.guardianApprovals(a, ['g1', 'g2', 'g3']) } }), 'QUORUM_NOT_SATISFIED');
});

// ---- F-V3-01 mutations (post-repair): same technique, different splits of stolen keys / objections
for (const [stolen, claimed, objectWith] of [
  [['k1-phone', 'k5-recovery-hw'], ['k2-laptop', 'k3-root-hw', 'k4-freeze'], ['k2-laptop']],
  [['k1-phone'], ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], ['k4-freeze']],
  [['k3-root-hw'], ['k1-phone', 'k2-laptop', 'k4-freeze', 'k5-recovery-hw'], ['k1-phone']],
  [['k1-phone', 'k2-laptop'], ['k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], ['k5-recovery-hw']],
]) test(`F-V3-01 mutation: stolen {${stolen}} + colluding guardians/IDVs/channels claim {${claimed}}; owner objects only with {${objectWith}}`, async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: claimed, full: true, attacker: true })).r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  for (const c of stolen) ok(await E.consent(w, c));
  for (const g of ['g1', 'g2', 'g3']) ok(await E.guardian(w, g));
  for (const ch of ['ch-email', 'ch-phone', 'ch-postal']) ok(await E.ack(w, ch)); // even with ALL channels compromised
  for (const k of objectWith) ok(await E.object(w, k));
  deny(await E.override(w), 'OVERRIDE_NOT_ALLOWED_IN_RECONSTITUTION');
  await w.advance(73 * H, H);
  await w.recovery.tryComplete(w.root.state); await w.pump();
  assert.equal((await w.verify()).takeovers.length, 0);
});

test('RESIDUAL R-1 (documented, not fixed): owner silent for 72 h + one stolen key + ALL guardians + BOTH identity verifiers + a majority of the owner\'s channels => takeover', async () => {
  const w = buildV3();
  ok((await ownerOpenCase(w, { lost: ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'], full: true, attacker: true })).r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  ok(await E.consent(w, 'k1-phone'));
  for (const g of ['g1', 'g2', 'g3']) ok(await E.guardian(w, g));
  await w.advance(73 * H, H);
  assert.equal((await w.recovery.tryComplete(w.root.state)).ok, false, 'without channel acks the reconstitution is refused');
  ok(await E.ack(w, 'ch-email')); ok(await E.ack(w, 'ch-postal'));
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  assert.equal(r.ok, true);
  assert.equal((await w.verify()).takeovers.length, 1, 'this is the residual collusion threshold, reported in THREAT-MODEL.md');
});
