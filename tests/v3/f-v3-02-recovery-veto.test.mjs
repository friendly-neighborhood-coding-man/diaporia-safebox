// F-V3-02 (found by red-team campaign A, thief scenario, Opus 4.8): a single stolen notification channel (or a single
// compromised guardian) could veto the owner's minority-loss recovery forever. The override required the
// reconstitution guardian quorum (3), so one compromised guardian of three made the HOLD permanent. For a lost ROOT or
// RECOVERY key there is no governance refill route, so the owner was locked out of governance for good.
// Expected (post-repair): on the RECOVERY path (<= 50 % lost), with EVERY surviving credential's consent, identity and the
// normal guardian quorum, the owner can override channel / claimed-lost-key / minority guardian objections; every
// stronger objection (survivor key, guardian majority, reconstitution path) still cannot be overridden.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV3 } from '../../src/v3/world.mjs';
import { ownerOpenCase, evidence as E } from '../../src/v3/recovery/sim.mjs';
import { survivors } from '../../src/v3/root/chain.mjs';

const H = 3600_000;
const ok = (r, m = '') => { assert.equal(r.ok, true, m + JSON.stringify(r.error)); return r.result; };
const deny = (r, code) => { assert.equal(r.ok, false, 'expected denial ' + code); assert.match(`${r.error.code}:${r.error.detail ?? ''}`, new RegExp(code)); };
const cs = (w) => w.root.state.case;

async function ownerCase(lost, { guardians = ['g2', 'g3'], consentAll = true } = {}) {
  const w = buildV3();
  const o = await ownerOpenCase(w, { lost }); ok(o.r);
  ok(await E.identity(w, 'idv-1'));
  const surv = survivors(w.root.state, cs(w), w.now());
  for (const c of consentAll ? surv : surv.slice(1)) ok(await E.consent(w, c));
  for (const g of guardians) ok(await E.guardian(w, g));
  for (const ch of ['ch-email', 'ch-postal']) ok(await E.ack(w, ch));
  return w;
}
async function finish(w) {
  await w.advance(Math.max(0, cs(w).openedAt + Number(w.root.state.config.windowMs) - w.now()) + 60_000, H);
  const r = await w.recovery.tryComplete(w.root.state); await w.pump();
  return { r, outcome: w.root.state.caseHistory.at(-1)?.outcome, case: cs(w) };
}

for (const [label, lost, attack] of [
  ['stolen channel objects (campaign A replay)', ['k1-phone'], (w) => E.ack(w, 'ch-phone', 'OBJECTION')],
  ['one compromised guardian objects', ['k1-phone'], (w) => E.guardian(w, 'g1', 'OBJECT')],
  ['stolen ROOT key objects as claimed-lost subject + stolen channel', ['k3-root-hw'], async (w) => { await E.object(w, 'k3-root-hw'); return E.ack(w, 'ch-phone', 'OBJECTION'); }],
  ['lost RECOVERY key: compromised guardian + channel object', ['k5-recovery-hw'], async (w) => { await E.guardian(w, 'g1', 'OBJECT'); return E.ack(w, 'ch-phone', 'OBJECTION'); }],
]) {
  test(`F-V3-02 exact replay: ${label} -> owner overrides with all-survivor consent + normal guardian quorum and recovers`, async () => {
    const w = await ownerCase(lost);
    ok(await attack(w));
    assert.equal(cs(w).state, 'HOLD');
    ok(await E.override(w), 'owner override: ');
    const f = await finish(w);
    assert.equal(f.outcome, 'RECOVERED', JSON.stringify(f.r));
    for (const l of lost) assert.notEqual(w.root.state.creds[l].status, 'active');
    const v = await w.verify();
    assert.equal(v.takeovers.length, 0); assert.equal(v.unauthorizedFinancial?.length ?? 0, 0);
  });
}

test('F-V3-02 mutation: missing ONE survivor consent -> override denied', async () => {
  const w = await ownerCase(['k1-phone'], { consentAll: false });
  ok(await E.ack(w, 'ch-phone', 'OBJECTION'));
  deny(await E.override(w), 'OVERRIDE_NEEDS_ALL_SURVIVOR_CONSENTS');
});

test('F-V3-02 mutation: below the normal guardian quorum -> override denied', async () => {
  const w = await ownerCase(['k1-phone'], { guardians: ['g2'] });
  ok(await E.ack(w, 'ch-phone', 'OBJECTION'));
  deny(await E.override(w), 'OVERRIDE_NEEDS_GUARDIAN_QUORUM');
});

test('F-V3-02 mutation: guardian objections not outnumbered by approvals -> override denied', async () => {
  const w = await ownerCase(['k1-phone'], { guardians: ['g3'] });
  ok(await E.guardian(w, 'g1', 'OBJECT')); ok(await E.guardian(w, 'g2', 'OBJECT'));
  deny(await E.override(w), 'OVERRIDE_NEEDS_GUARDIAN_QUORUM|OVERRIDE_GUARDIAN_OBJECTIONS_NOT_OUTNUMBERED');
});

test('F-V3-02 mutation: a SURVIVING credential objection is never overridable', async () => {
  const w = await ownerCase(['k1-phone']);
  ok(await E.object(w, 'k2-laptop'));
  deny(await E.override(w), 'NOTHING_TO_OVERRIDE');
});

test('F-V3-02 mutation: reconstitution path keeps the strict rules (guardian objection not overridable)', async () => {
  const w = buildV3();
  const o = await ownerOpenCase(w, { lost: ['k1-phone', 'k2-laptop', 'k3-root-hw'], full: true }); ok(o.r);
  ok(await E.identity(w, 'idv-1')); ok(await E.identity(w, 'idv-2'));
  for (const c of survivors(w.root.state, cs(w), w.now())) ok(await E.consent(w, c));
  for (const g of ['g2', 'g3']) ok(await E.guardian(w, g));
  ok(await E.guardian(w, 'g1', 'OBJECT'));
  deny(await E.override(w), 'NOTHING_TO_OVERRIDE|OVERRIDE_');
});

test('F-V3-02 mutation: a guardian that approves and then objects is not counted on both sides', async () => {
  const w = await ownerCase(['k1-phone'], { guardians: ['g2', 'g3'] });
  ok(await E.guardian(w, 'g2', 'OBJECT')); ok(await E.guardian(w, 'g3', 'OBJECT'));
  deny(await E.override(w), 'OVERRIDE_NEEDS_GUARDIAN_QUORUM|OVERRIDE_GUARDIAN_OBJECTIONS_NOT_OUTNUMBERED');
});
