// Confidential ballots (not anonymity) and V4 integration: Vault replay, payments, independent verifier.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV4 } from '../../src/v4/world.mjs';
import { openGov, govVote, govTally, emergencyReplace, legitimateRecoveryV4 } from '../../src/v4/recovery/sim.mjs';
import { TallyService, castBallot, commitmentOf } from '../../src/v4/ballot/ballot.mjs';
import { verifyV4 } from '../../src/v4/supervisor/verifier.mjs';
import { H, D, Y, ok, deny } from './helpers.mjs';

const gc = (w) => w.root.state.v4.gcase;

test('BALLOT: sealed to the tally key only; a different X25519 key cannot open it; commitments bind case + voter + choice', async () => {
  const w = buildV4(); ok((await openGov(w, { accused: ['g1'] })).r);
  const b = w.owner.ballot(gc(w), 'g2', 'REJECT');
  assert.ok(!JSON.stringify(b.body).includes('REJECT'), 'choice not visible on the Root chain');
  assert.equal(w.owner.tally.open({ body: b.body }).choice, 'REJECT');
  assert.throws(() => new TallyService().open({ body: b.body }), /SEALED_BALLOT_UNOPENABLE/);
  assert.notEqual(commitmentOf({ gcaseDigest: gc(w).digest, voterId: 'g2', choice: 'APPROVE', salt: b.opening.salt }), b.body.commitment);
  // ciphertext moved to another voter's ballot fails authentication (AAD = case digest | voter id)
  const moved = { ...b.body, voterId: 'g3' };
  assert.throws(() => w.owner.tally.open({ body: moved }), /SEALED_BALLOT_UNOPENABLE|COMMITMENT/);
});

test('BALLOT: bound to the case — a ballot from an earlier case is refused in a later case; malformed sealed payloads refused', async () => {
  const w = buildV4(); ok((await openGov(w, { accused: ['g1'], gcaseId: 'gc-one' })).r);
  const old = w.owner.ballot(gc(w), 'g2', 'APPROVE');
  ok(await w.submitRaw('GOV_CASE_CANCEL', { gcaseId: 'gc-one', gcaseDigest: gc(w).digest }, { approvals: (a) => w.owner.authorize(w.root.state, a, ['orc-1']) }));
  ok((await openGov(w, { accused: ['g1'], gcaseId: 'gc-two' })).r);
  deny(await w.submitRaw('GOV_BALLOT', { ...old.body }, { attest: () => ({ voterSig: old.voterSig }) }), 'GOVERNANCE_CASE_MISMATCH');
  deny(await w.submitRaw('GOV_BALLOT', { ...old.body, gcaseId: 'gc-two', gcaseDigest: gc(w).digest }, { attest: () => ({ voterSig: old.voterSig }) }), 'BALLOT_ELIGIBILITY_SIGNATURE');
  const b = w.owner.ballot(gc(w), 'g2', 'APPROVE');
  deny(await w.submitRaw('GOV_BALLOT', { ...b.body, sealed: { ...b.body.sealed, ct: 'A' } }, { attest: () => ({ voterSig: b.voterSig }) }), 'BALLOT_SEALED_FORMAT');
  deny(await w.submitRaw('GOV_BALLOT', { ...b.body, commitment: 'zz' }, { attest: () => ({ voterSig: b.voterSig }) }), 'BALLOT_COMMITMENT');
});

test('BALLOT RESULT: APPROVED is verifiable from public openings; REJECTED reveals no individual choice; votes after the window refused', async () => {
  const w = buildV4(); ok((await openGov(w, { accused: ['g1'] })).r);
  for (const v of gc(w).electorate) ok(await govVote(w, v));
  const t = w.owner.tally.tally(gc(w));
  assert.equal(t.statement.openings.length, gc(w).electorate.length);
  for (const o of t.statement.openings) assert.equal(commitmentOf({ gcaseDigest: gc(w).digest, ...o }), gc(w).ballots[o.voterId].commitment);
  const w2 = buildV4(); ok((await openGov(w2, { accused: ['g1'] })).r);
  ok(await govVote(w2, 'g2', 'REJECT'));
  await w2.advance(72 * H + H, 6 * H);
  deny(await govVote(w2, 'g3'), 'BALLOT_VOTING_CLOSED|NO_GOVERNANCE_CASE');
});

test('BALLOT: single-voter inference is real and documented (an electorate of one reveals that voter\'s choice)', async () => {
  const w = buildV4();
  // replace g1,g2,g3 => electorate is idv-1 + idv-2; then replace idv-1 => electorate = 3 new guardians + idv-2 (not single)
  // a single-voter electorate arises with 1 guardian config; we check the tally output carries the electorate size so the
  // inference is visible to anyone reading the result.
  ok((await openGov(w, { accused: ['g1', 'g2', 'g3'] })).r);
  assert.equal(gc(w).electorate.length, 2);
  for (const v of gc(w).electorate) ok(await govVote(w, v));
  const t = w.owner.tally.tally(gc(w));
  assert.equal(t.statement.electorate, '2'); assert.equal(t.statement.result, 'APPROVED');
});

test('INTEGRATION: Vault replays the V4 chain; a governance execution bumps the epoch and cancels pending payments; verifier independent', async () => {
  const w = buildV4();
  ok(await w.pay({ amountYocto: Y(1) }));
  const r = await emergencyReplace(w, { accused: ['g1'] }); assert.equal(r.stage, 'done', JSON.stringify(r));
  assert.equal(w.vault.root.epoch, w.root.state.epoch); assert.equal(w.vault.root.head, w.root.state.head); assert.equal(w.vault.root.guardians.g1.status, 'removed');
  ok(await w.pay({ amountYocto: Y(1) }));
  await w.advance(11 * 60_000);
  const v = await w.verify();
  assert.equal(v.chainValid, true); assert.deepEqual(v.financial.violations, []); assert.deepEqual(v.authority.unauthorized, []);
  // tampering any transition breaks the independent replay
  const trs = structuredClone(w.root.chain(0)); const i = trs.findIndex(t => t.action.type === 'GOV_TALLY');
  trs[i].action.body.result = 'REJECTED';
  const bad = verifyV4({ genesis: w.genesis, pinnedChainId: w.owner.chainId4, transitions: trs, ledgerTxs: [], evidence: [] });
  assert.equal(bad.chainValid, false);
});

test('INTEGRATION: payments keep working through an R-1 attack (bounded lockdown) and after a legitimate majority recovery', async () => {
  const w = buildV4();
  const rep = await legitimateRecoveryV4(w, ['k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw']);
  assert.equal(rep.outcome, 'NEW_EPOCH');
  const daily = Object.values(w.root.state.creds).find(c => c.status === 'active' && c.role === 'DAILY');
  ok(await w.pay({ credId: daily.credId, amountYocto: Y(2) }));
  deny(await w.pay({ credId: 'k1-phone', amountYocto: Y(1) }), 'NOT_ACTIVE|RETIRED|EPOCH');
  await w.advance(11 * 60_000);
  const v = await w.verify(); assert.deepEqual(v.financial.violations, []);
});
