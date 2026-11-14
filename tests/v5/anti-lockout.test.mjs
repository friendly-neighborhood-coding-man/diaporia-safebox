// Mission 2 mandatory regression + variants: independent protective-hold records, effective restriction = union of holds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, D, freezeBy, holdBy, confirm, release, contest, status, active } from './helpers.mjs';
import { legitimateRecoveryV4 } from '../../src/v4/recovery/sim.mjs';

test('MANDATORY: stolen K1 FREEZE, K2 independently holds, owner revokes K1 => K1 hold removable, K2 hold stays', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));                                  // attacker with stolen K1
  ok(await holdBy(w, 'k2-laptop', 'h-k2', { reinforces: 'h-k1' }));            // legitimate K2: vault must remain frozen
  assert.deepEqual(active(w), ['h-k1', 'h-k2']);
  ok(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw'])); // owner revokes K1
  assert.equal(status(w)['k1-phone'], 'revoked');
  assert.equal(w.hold('h-k1').status, 'RELEASED_ISSUER_REVOKED');             // K1-origin hold no longer restricts
  assert.equal(w.hold('h-k2').status, 'ACTIVE');                              // K2-origin hold remains effective
  assert.equal(w.frozen(), true);
  ok(await release(w, ['k2-laptop'], 'h-k2'));                                // only K2 (its issuer) can lift it
  assert.equal(w.frozen(), false);
});

test('MANDATORY variant: K2 CONFIRMS K1 hold instead; after revoking K1 the hold stays until K2 releases it', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await confirm(w, 'k2-laptop', 'h-k1'));
  ok(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw']));
  assert.equal(w.hold('h-k1').status, 'ACTIVE', 'K2 confirmation keeps it in force');
  assert.equal(w.frozen(), true);
  ok(await release(w, ['k2-laptop'], 'h-k1'));                                // K1 no longer a valid party: K2 alone suffices
  assert.equal(w.frozen(), false);
});

test('reverse order: K2 holds first, stolen K1 freezes later; revoking K1 leaves K2 hold', async () => {
  const w = buildV5();
  ok(await holdBy(w, 'k2-laptop', 'h-k2'));
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw']));
  assert.deepEqual(active(w), ['h-k2']);
  assert.equal(w.frozen(), true);
});

test('release of a multi-party hold needs every valid party; one party cannot lift another party\'s hold', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await holdBy(w, 'k2-laptop', 'h-k2'));
  deny(await release(w, ['k1-phone'], 'h-k2'), 'RELEASE_NEEDS_EVERY_VALID_PARTY');
  ok(await release(w, ['k1-phone'], 'h-k1'));
  assert.equal(w.frozen(), true, 'K2 hold still active');
  ok(await confirm(w, 'k4-freeze', 'h-k2'));
  deny(await release(w, ['k2-laptop'], 'h-k2'), 'RELEASE_NEEDS_EVERY_VALID_PARTY');
  ok(await release(w, ['k2-laptop', 'k4-freeze'], 'h-k2'));
  assert.equal(w.frozen(), false);
});

test('concurrent freezes from three credentials; each released independently; union semantics', async () => {
  const w = buildV5();
  for (const c of ['k1-phone', 'k2-laptop', 'k4-freeze']) ok(await freezeBy(w, c));
  for (const c of ['k1-phone', 'k2-laptop']) { ok(await release(w, [c], 'h-' + c)); assert.equal(w.frozen(), true); }
  ok(await release(w, ['k4-freeze'], 'h-k4-freeze'));
  assert.equal(w.frozen(), false);
});

test('repeated reinforcement by the same issuer is refused; issuer budget bounds re-freezing', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h1'));
  deny(await holdBy(w, 'k1-phone', 'h1b'), 'HOLD_DUPLICATE_BY_SAME_ISSUER');
  // the attacker re-freezes after each expiry until the 96 h / 30 d budget is gone
  let n = 1;
  for (let i = 0; i < 10; i++) { await w.advance(24 * H + 60_000, H); const r = await freezeBy(w, 'k1-phone', 'h1-' + i); if (!r.ok) { deny(r, 'HOLD_ISSUER_BUDGET_EXHAUSTED'); break; } n++; }
  assert.equal(n, 4, 'four 24 h provisional holds = 96 h budget');
  assert.equal(w.frozen(), false);
});

test('provisional hold expires after 24 h unless escalated; escalation needs distinct role + trusted confirmation', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h1'));
  ok(await confirm(w, 'k2-laptop', 'h1'));                                    // same role (DAILY): stays provisional
  assert.equal(w.hold('h1').class, 'PROVISIONAL_HOLD');
  ok(await confirm(w, 'k3-root-hw', 'h1'));                                   // ROOT on trusted display => CONFIRMED_OWNER_HOLD
  assert.equal(w.hold('h1').class, 'CONFIRMED_OWNER_HOLD');
  await w.advance(3 * D, 6 * H);
  assert.equal(w.frozen(), true, 'confirmed holds never expire by timer');
  deny(await release(w, ['k1-phone', 'k2-laptop'], 'h1'), 'RELEASE_NEEDS_EVERY_VALID_PARTY');
  ok(await release(w, ['k1-phone', 'k2-laptop', 'k3-root-hw'], 'h1'));
});

test('unconfirmed provisional hold lapses at 24 h; housekeeping records it', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h1'));
  await w.advance(24 * H + 120_000, H);
  assert.equal(w.frozen(), false);
  assert.equal(w.hold('h1').status, 'EXPIRED');
});

test('verified incident freeze: never on a timer, never by contest or issuer revocation; needs quorum + repair certificate for THIS hold', async () => {
  const w = buildV5();
  ok(await w.supervisorFreeze('inc-1'));
  await w.advance(10 * D, 12 * H);
  assert.equal(w.frozen(), true);
  deny(await contest(w, 'k1-phone', ['inc-1']), 'CONTEST_(HOLD_NOT_ATTRIBUTABLE|CANNOT_BYPASS)');
  deny(await release(w, ['k1-phone', 'k3-root-hw'], 'inc-1'), 'RELEASE_ATTESTATION|REPAIR');
  const cert = (freezeId) => w.owner.repairCert({ freezeId, verdict: 'REPAIRED', exactReplay: 'DENIED_FOR_INVARIANT', mutations: 'ALL_DENIED', regression: 'PASS', legitimate: 'PASS', candidate: 'fix-1' });
  deny(await release(w, ['k1-phone', 'k3-root-hw'], 'inc-1', { attestation: () => ({ repair: cert('other') }) }), 'REPAIR_CERT_WRONG_FREEZE');
  deny(await release(w, ['k1-phone'], 'inc-1', { attestation: () => ({ repair: cert('inc-1') }) }), 'APPROVALS_INVALID|QUORUM');
  ok(await release(w, ['k1-phone', 'k3-root-hw'], 'inc-1', { attestation: () => ({ repair: cert('inc-1') }) }));
  assert.equal(w.frozen(), false);
});

test('supervisor breach hold + owner hold: releasing the incident freeze leaves the owner hold', async () => {
  const w = buildV5();
  ok(await w.supervisorFreeze('inc-1'));
  ok(await freezeBy(w, 'k4-freeze', 'h-owner'));
  const cert = { statement: { freezeId: 'inc-1', verdict: 'REPAIRED', exactReplay: 'DENIED_FOR_INVARIANT', mutations: 'ALL_DENIED', regression: 'PASS', legitimate: 'PASS', candidate: 'fix-1' } };
  ok(await release(w, ['k1-phone', 'k3-root-hw'], 'inc-1', { attestation: () => ({ repair: w.owner.repairCert(cert.statement) }) }));
  assert.equal(w.frozen(), true);
  assert.deepEqual(active(w), ['h-owner']);
});

test('CONTEST_PROTECTIVE_HOLD: ORC + independent owner credential revokes the suspect and releases only its exclusive holds', async () => {
  const w = buildV5();
  ok(await holdBy(w, 'k1-phone', 'h-k1', { dur: 20 * H }));
  ok(await w.cmd('SUSPEND', { credId: 'k3-root-hw', holdId: 'q-k3' }, ['k1-phone']));   // thief quarantines the owner's root key
  ok(await holdBy(w, 'k2-laptop', 'h-k2'));
  ok(await holdBy(w, 'k1-phone', 'm-c', { scope: { kind: 'MERCHANT', target: 'merchant-c.mock' }, dur: H }));
  deny(await holdBy(w, 'k1-phone', 'm-b', { scope: { kind: 'MERCHANT', target: 'merchant-b.mock' }, dur: H }), 'HOLD_ISSUER_(BUDGET_EXHAUSTED|ACTIVE_LIMIT)');
  ok(await confirm(w, 'k4-freeze', 'm-c'));                                               // owner independently agrees merchant-c should wait
  // suspended k3 may authenticate for the contest only
  const r = ok(await contest(w, 'k1-phone', ['h-k1', 'q-k3', 'm-c']));
  const ev = r.effects.find(e => e.type === 'CONTEST_RESOLVED');
  assert.deepEqual(ev.released.sort(), ['h-k1', 'q-k3']);
  assert.deepEqual(ev.kept, ['m-c']);
  assert.equal(status(w)['k1-phone'], 'revoked');
  assert.equal(status(w)['k3-root-hw'], 'active');
  assert.equal(w.hold('m-c').status, 'ACTIVE');
  assert.equal(w.frozen(), true, 'K2 owner hold not overridden');
});

test('CONTEST cannot: pay, run without ORC, be signed by the suspect, target holds not issued by the suspect', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await holdBy(w, 'k2-laptop', 'h-k2'));
  deny(await contest(w, 'k1-phone', ['h-k1'], ['k2-laptop', 'k3-root-hw']), 'CONTEST_NEEDS_ORC');
  deny(await contest(w, 'k1-phone', ['h-k1'], ['orc-1', 'k1-phone']), 'CONTEST_SIGNED_BY_SUSPECT');
  deny(await contest(w, 'k1-phone', ['h-k2']), 'CONTEST_HOLD_NOT_ATTRIBUTABLE_TO_SUSPECT');
  deny(await contest(w, 'k1-phone', ['h-k1'], ['orc-1', 'k4-freeze']), 'CONTEST_NEEDS_INDEPENDENT_OWNER_CREDENTIAL');
  const r = await w.pay({ credId: 'k2-laptop' });
  assert.equal(r.ok, false, 'frozen: no payment');
});

test('owner-origin hold: the owner\'s own freeze survives revocation of an unrelated stolen key', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k4-freeze', 'h-own'));
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw']));
  assert.deepEqual(active(w), ['h-own']);
});

test('crash recovery: hold registry and effective freeze survive Root and Vault restarts (replayed from the chain)', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await holdBy(w, 'k2-laptop', 'h-k2'));
  const before = w.root.state.head;
  w.restartRoot(); w.restartVault(); await w.pump();
  assert.equal(w.root.state.head, before);
  assert.deepEqual(active(w), ['h-k1', 'h-k2']);
  assert.equal(w.vault.root.freeze.active, true);
  ok(await w.ownerAct('REVOKE', { credId: 'k1-phone', reason: 'stolen' }, ['k2-laptop', 'k3-root-hw']));
  w.restartRoot(); await w.pump();
  assert.deepEqual(active(w), ['h-k2']);
});

test('full V4 recovery of a stolen key lifts the thief\'s holds only (anti-lockout through recovery)', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h-k1'));
  ok(await w.cmd('SUSPEND', { credId: 'k3-root-hw', holdId: 'q-k3' }, ['k1-phone']));
  ok(await holdBy(w, 'k2-laptop', 'h-k2'));
  const rep = await legitimateRecoveryV4(w, ['k1-phone']);
  assert.match(rep.outcome, /RECOVERED|EXECUTED|OK/, JSON.stringify(rep.steps.slice(-3)) + rep.outcome);
  assert.equal(status(w)['k1-phone'] === 'active', false);
  assert.deepEqual(active(w), ['h-k2']);
  assert.equal(status(w)['k3-root-hw'], 'active');
});
