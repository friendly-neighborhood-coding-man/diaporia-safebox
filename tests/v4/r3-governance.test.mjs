// R-3 closure: emergency replacement of compromised / misbehaving / unavailable / withdrawing Guardians and identity
// verifiers. An accusation alone proves nothing; proven members are excluded from the electorate; the remaining eligible
// members decide unanimously through sealed ballots; an independent owner quorum (2 distinct owner roles) opens the case;
// replacement is atomic and 1:1 with proof of possession; a 24 h notified delay precedes execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV4 } from '../../src/v4/world.mjs';
import { openGov, govVote, govTally, govExecute, emergencyReplace, verdicts, legitimateRecoveryV4 } from '../../src/v4/recovery/sim.mjs';
import { H, D, Y, ok, deny } from './helpers.mjs';
import { V4_DOMAINS } from '../../src/v4/common/v4.mjs';

const G = 'GUARDIAN_EMERGENCY_REPLACE', I = 'IDENTITY_VERIFIER_EMERGENCY_REPLACE';
const gs = (w) => Object.entries(w.root.state.guardians).filter(([, g]) => g.status === 'active').map(([k]) => k).sort();
const gc = (w) => w.root.state.v4.gcase;
const snapshot = (w) => JSON.stringify({ p: w.root.state.purposeDigest, m: w.root.state.matrixDigest, c: Object.values(w.root.state.creds).map(c => c.credId + c.status + c.publicKey).sort() });

for (const owners of [['k2-laptop', 'k3-root-hw'], ['k2-laptop', 'k3-root-hw', 'k5-recovery-hw']]) {
  test(`GUARDIAN 2/3 compromised, owner ${owners.join('+')}: replaced atomically, epoch bumps, nothing else changes`, async () => {
    const w = buildV4(); const s0 = snapshot(w), e0 = w.root.state.epoch;
    const r = await emergencyReplace(w, { accused: ['g1', 'g2'], owners });
    assert.equal(r.stage, 'done', JSON.stringify(r)); assert.equal(r.outcome, 'EXECUTED');
    assert.deepEqual(gs(w).filter(g => g.startsWith('g-new')).length, 2); assert.equal(gs(w).length, 3);
    assert.equal(w.root.state.guardians.g1.status, 'removed'); assert.ok(w.root.state.v4.disqualified.g1);
    assert.equal(w.root.state.epoch, e0 + 1); assert.equal(snapshot(w), s0, 'no payment / Purpose / credential authority touched');
    const v = await w.verify(); assert.equal(v.chainValid, true); assert.deepEqual(v.authority.unauthorized, []);
    assert.deepEqual(v.participants.removed.sort(), ['g1', 'g2']);
    // the new guardians work in a later recovery
    const rep = await legitimateRecoveryV4(w, ['k2-laptop'], { orc: null, honestGuardians: gs(w).filter(g => g.startsWith('g-new')) });
    assert.equal(rep.outcome, 'RECOVERED', JSON.stringify(rep));
  });
}

test('GUARDIAN 3/3 compromised: electorate = both identity verifiers (unanimous); quorum floor kept', async () => {
  const w = buildV4();
  const r = await emergencyReplace(w, { accused: ['g1', 'g2', 'g3'] });
  assert.equal(r.stage, 'done', JSON.stringify(r));
  assert.equal(gs(w).length, 3); assert.ok(gs(w).every(g => g.startsWith('g-new')));
});

test('IDV 1/2 and 2/2 compromised (owner K2+K3+K5), and combined guardians-then-IDVs', async () => {
  let w = buildV4();
  let r = await emergencyReplace(w, { procedure: I, accused: ['idv-1'], owners: ['k2-laptop', 'k3-root-hw', 'k5-recovery-hw'] });
  assert.equal(r.stage, 'done', JSON.stringify(r)); assert.deepEqual(Object.keys(w.root.state.idvs).length, 2);
  w = buildV4();
  r = await emergencyReplace(w, { procedure: I, accused: ['idv-1', 'idv-2'] });
  assert.equal(r.stage, 'done', JSON.stringify(r)); assert.ok(!w.root.state.idvs['idv-1'] && !w.root.state.idvs['idv-2']);
  // combined: 2 guardians + 1 IDV compromised. Second case's electorate excludes the disqualified guardians.
  w = buildV4();
  r = await emergencyReplace(w, { accused: ['g1', 'g2'] }); assert.equal(r.stage, 'done');
  const o = await openGov(w, { procedure: I, accused: ['idv-2'] }); ok(o.r);
  assert.ok(!gc(w).electorate.includes('g1') && !gc(w).electorate.includes('g2') && !gc(w).electorate.includes('idv-2'));
  for (const v of gc(w).electorate) ok(await govVote(w, v));
  ok(await govTally(w)); ok(await govExecute(w));
  assert.equal((await w.verify()).chainValid, true);
});

test('IMPOSSIBLE: every guardian AND every identity verifier compromised => empty electorate is never valid (reported, authority unchanged)', async () => {
  const w = buildV4(); const s0 = snapshot(w);
  // one case cannot cover both procedures; accusing the 2 IDVs leaves the 3 (compromised) guardians as electorate,
  // who simply reject. Accusing all guardians with the IDVs disqualified first is impossible without the guardians.
  const r = await emergencyReplace(w, { procedure: I, accused: ['idv-1', 'idv-2'] }, { choice: 'REJECT' });
  assert.equal(r.stage, 'closed'); assert.equal(r.outcome, 'REJECTED');
  // a world where the IDVs were already disqualified and all guardians are accused: empty electorate
  const w2 = buildV4();
  ok((await emergencyReplace(w2, { procedure: I, accused: ['idv-1', 'idv-2'] })).o.r);
  // after replacement the new IDVs are eligible; simulate the extreme: accuse guardians AND mark both new IDVs disqualified
  for (const k of Object.keys(w2.root.state.idvs)) w2.root.state.v4.disqualified[k] = { ground: 'TEST', gcaseId: '-', at: '0' };
  deny((await openGov(w2, { accused: ['g1', 'g2', 'g3'] })).r, 'EMERGENCY_ELECTORATE_EMPTY');
  assert.equal(snapshot(w), s0);
});

test('FORGED / INSUFFICIENT ACCUSATIONS: one verdict, duplicated adjudicator, forged signature, wrong subject key, wrong finding, expired verdict, unknown adjudicator, bare accusation', async () => {
  const w = buildV4();
  deny((await openGov(w, { accused: ['g1'], adj: ['adj-1'] })).r, 'ACCUSATION_NOT_ESTABLISHED');
  deny((await openGov(w, { accused: ['g1'], evidence: [...verdicts(w, 'g1', ['adj-1']), ...verdicts(w, 'g1', ['adj-1'])] })).r, 'ACCUSATION_NOT_ESTABLISHED');
  const forged = verdicts(w, 'g1', ['adj-1', 'adj-2']); forged[1].sig = forged[0].sig;
  deny((await openGov(w, { accused: ['g1'], evidence: forged })).r, 'VERDICT_SIGNATURE');
  deny((await openGov(w, { accused: ['g1'], evidence: verdicts(w, 'g1', ['adj-1', 'adj-2'], { key: w.root.state.guardians.g2.publicKey }) })).r, 'VERDICT_WRONG_SUBJECT');
  deny((await openGov(w, { accused: ['g1'], evidence: verdicts(w, 'g1', ['adj-1', 'adj-2'], { finding: 'MISCONDUCT' }) })).r, 'VERDICT_WRONG_FINDING');
  deny((await openGov(w, { accused: ['g1'], evidence: verdicts(w, 'g1', ['adj-1', 'adj-2'], { at: w.now() - 8 * D }) })).r, 'VERDICT_NOT_CURRENT');
  const unk = verdicts(w, 'g1', ['adj-1', 'adj-2']); unk[1].adjudicatorId = 'adj-9';
  deny((await openGov(w, { accused: ['g1'], evidence: unk })).r, 'VERDICT_UNKNOWN_ADJUDICATOR');
  deny((await openGov(w, { accused: ['g1'], evidence: [] })).r, 'ACCUSATION_NOT_ESTABLISHED');
  // a verdict for another account / chain
  const other = verdicts(w, 'g1', ['adj-1', 'adj-2']).map(v => w.owner.verdict(v.adjudicatorId, { ...v.statement, at: w.now(), chainId: 'f'.repeat(64) }));
  deny((await openGov(w, { accused: ['g1'], evidence: other })).r, 'VERDICT_WRONG_ACCOUNT');
  assert.equal(gc(w), null);
});

test('GUARDIAN EQUIVOCATION: two contradictory signatures by the guardian key are a self-contained compromise proof', async () => {
  const w = buildV4();
  const dig = 'ab'.repeat(32);
  const k = w.owner.guardianKeys.g3; const { V3_DOMAINS } = await import('../../src/v3/common/canon.mjs');
  const ev = [{ kind: 'EQUIVOCATION', subjectId: 'g3', actionDigest: dig, sigApprove: k.signStatement(V3_DOMAINS.GUARDIAN, { actionDigest: dig, decision: 'APPROVE' }), sigObject: k.signStatement(V3_DOMAINS.GUARDIAN, { actionDigest: dig, decision: 'OBJECT' }) }];
  const bad = [{ ...ev[0], sigObject: ev[0].sigApprove }];
  deny((await openGov(w, { accused: ['g3'], evidence: bad })).r, 'EQUIVOCATION_PROOF_INVALID');
  const r = await emergencyReplace(w, { accused: ['g3'], evidence: ev });
  assert.equal(r.stage, 'done', JSON.stringify(r));
});

test('OWNER QUORUM: duplicates, same role twice, FREEZE key, single key, attacker with stolen K1 => all refused; K1+ORC accepted', async () => {
  const w = buildV4();
  deny((await openGov(w, { accused: ['g1'], owners: ['k3-root-hw', 'k3-root-hw'] })).r, 'DUPLICATE_APPROVAL');
  deny((await openGov(w, { accused: ['g1'], owners: ['k1-phone', 'k2-laptop'] })).r, 'EMERGENCY_OWNER_QUORUM_NOT_MET');
  deny((await openGov(w, { accused: ['g1'], owners: ['k4-freeze', 'k3-root-hw'] })).r, 'ROLE_NOT_IN_EMERGENCY_OWNER_QUORUM');
  deny((await openGov(w, { accused: ['g1'], owners: ['k1-phone'] })).r, 'EMERGENCY_OWNER_QUORUM_SHAPE');
  // software-only confirmations (laptop passkey + phone WITHOUT protected confirmation) are lower assurance: refused
  deny((await openGov(w, { accused: ['g1'], owners: ['k2-laptop', 'k1-phone'], authOpts: { apc: false } })).r, 'EMERGENCY_OWNER_QUORUM_NOT_MET|TRUSTED_CONFIRMATION_REQUIRED');
  const r = await emergencyReplace(w, { accused: ['g1'], owners: ['k1-phone', 'orc-1'] });
  assert.equal(r.stage, 'done', JSON.stringify(r));
});

test('LOST ROOT (K3) or LOST RECOVERY (K5): the remaining owner roles (+ ORC) still form the quorum; lost K3+K5 needs the ORC', async () => {
  let w = buildV4();
  assert.equal((await emergencyReplace(w, { accused: ['g1'], owners: ['k2-laptop', 'k5-recovery-hw'] })).stage, 'done');
  w = buildV4();
  assert.equal((await emergencyReplace(w, { accused: ['g1'], owners: ['k1-phone', 'k3-root-hw'] })).stage, 'done');
  w = buildV4();
  deny((await openGov(w, { accused: ['g1'], owners: ['k1-phone', 'k2-laptop'] })).r, 'EMERGENCY_OWNER_QUORUM_NOT_MET');
  assert.equal((await emergencyReplace(w, { accused: ['g1'], owners: ['k2-laptop', 'orc-1'] })).stage, 'done');
});

test('QUORUM MANIPULATION: accused / outsider / duplicate voters, forged eligibility, lying tally, incomplete approval', async () => {
  const w = buildV4();
  ok((await openGov(w, { accused: ['g1'] })).r);
  deny(await govVote(w, 'g1'), 'BALLOT_VOTER_NOT_ELIGIBLE');
  w.owner.newParticipant('guardian', 'outsider', 'holder-out'); deny(await govVote(w, 'outsider'), 'BALLOT_VOTER_NOT_ELIGIBLE');
  ok(await govVote(w, 'g2'));
  deny(await govVote(w, 'g2'), 'BALLOT_DUPLICATE_VOTE');
  // eligibility signature by another member's key
  const b = w.owner.ballot(gc(w), 'g3', 'APPROVE'); const b2 = w.owner.ballot(gc(w), 'idv-1', 'APPROVE');
  deny(await w.submitRaw('GOV_BALLOT', b.body, { attest: () => ({ voterSig: b2.voterSig }) }), 'BALLOT_ELIGIBILITY_SIGNATURE');
  // APPROVED before everyone voted
  deny(await govTally(w), 'TALLY_PREMATURE|TALLY_APPROVAL_INCOMPLETE');
  ok(await govVote(w, 'g3')); ok(await govVote(w, 'idv-1')); ok(await govVote(w, 'idv-2', 'REJECT'));
  // a compromised tally key fabricating APPROVED: openings do not match the REJECT commitment
  const t = w.owner.tally.tally(gc(w)); assert.equal(t.statement.result, 'REJECTED'); assert.deepEqual(t.statement.openings, [], 'no ballot revealed on rejection');
  const ballots = Object.values(gc(w).ballots).map(x => w.owner.tally.open({ body: x }));
  const fake = { ...t.statement, result: 'APPROVED', openings: ballots.map(o => ({ ...o, choice: 'APPROVE' })) };
  deny(await w.submitRaw('GOV_TALLY', fake, { attest: () => ({ tallySig: w.owner.tally.signer.signObj(V4_DOMAINS.TALLY, fake) }) }), 'TALLY_OPENING_MISMATCH');
  // tampered statement without re-signing
  deny(await govTally(w, { tamper: (x) => { x.statement.result = 'APPROVED'; } }), 'TALLY_SIGNATURE');
  ok(await govTally(w));
  assert.equal(w.root.state.v4.gcaseHistory.at(-1).outcome, 'REJECTED'); assert.equal(w.root.state.guardians.g1.status, 'active');
});

test('REMOVAL WITHOUT REPLACEMENT and MALICIOUS REPLACEMENTS are refused', async () => {
  const w = buildV4();
  deny((await openGov(w, { accused: ['g1'], replacements: [] })).r, 'REMOVAL_WITHOUT_REPLACEMENT');
  const st = w.root.state;
  const mk = (over) => [{ ...w.owner.newParticipant('guardian', 'g-x', 'holder-x', 'will-fail'), ...over }];
  deny((await openGov(w, { accused: ['g1'], replacements: mk({}) })).r, 'REPLACEMENT_POP_INVALID');
  const good = (id, holder) => (gcaseId) => w.owner.newParticipant('guardian', id, holder, gcaseId);
  deny((await openGov(w, { accused: ['g1'], gcaseId: 'gc-a', replacements: [{ ...good('g-y', 'holder-y')('gc-a'), publicKey: st.guardians.g2.publicKey }] })).r, 'REPLACEMENT_KEY_NOT_INDEPENDENT|POP');
  deny((await openGov(w, { accused: ['g1'], gcaseId: 'gc-b', replacements: [good('g-z', 'alice')('gc-b')] })).r, 'REPLACEMENT_HOLDER_NOT_INDEPENDENT');
  deny((await openGov(w, { accused: ['g1'], gcaseId: 'gc-c', replacements: [good('g-w', 'guardian-2')('gc-c')] })).r, 'REPLACEMENT_HOLDER_NOT_INDEPENDENT');
  deny((await openGov(w, { accused: ['g1'], gcaseId: 'gc-d', replacements: [good('g2', 'holder-q')('gc-d')] })).r, 'REPLACEMENT_ID_IN_USE');
  // reusing the removed member's own key under a new id
  deny((await openGov(w, { accused: ['g1'], gcaseId: 'gc-e', replacements: [{ ...good('g-v', 'holder-v')('gc-e'), publicKey: st.guardians.g1.publicKey }] })).r, 'REPLACEMENT_KEY_NOT_INDEPENDENT|POP');
  // an ORC / owner key as a "guardian"
  deny((await openGov(w, { accused: ['g1'], gcaseId: 'gc-f', replacements: [{ ...good('g-u', 'holder-u')('gc-f'), publicKey: st.v4.orcs['orc-1'].publicKey }] })).r, 'REPLACEMENT_KEY_NOT_INDEPENDENT|POP');
  assert.equal(gc(w), null);
});

test('UNAVAILABLE is not malice: needs an unanswered liveness ping for 30 days; a reply resets it; the member is retired, not disqualified', async () => {
  const w = buildV4();
  deny((await openGov(w, { accused: ['g2'], ground: 'UNAVAILABLE' })).r, 'UNAVAILABILITY_NOT_ESTABLISHED');
  ok(await w.recovery.ping('g2'));
  await w.advance(10 * D, 6 * H);
  // the guardian answers: unavailability is not established even after 30 more days
  ok(await w.submitRaw('PARTICIPANT_LIVENESS_PONG', { participantId: 'g2' }, { attest: (a) => ({ participantSig: w.owner.livenessSign(a, 'g2') }) }));
  await w.advance(21 * D, 6 * H);
  deny((await openGov(w, { accused: ['g2'], ground: 'UNAVAILABLE' })).r, 'UNAVAILABILITY_NOT_ESTABLISHED');
  ok(await w.recovery.ping('g2'));
  deny(await w.recovery.ping('g2'), 'LIVENESS_PING_PENDING');
  await w.advance(30 * D + H, 12 * H);
  const r = await emergencyReplace(w, { accused: ['g2'], ground: 'UNAVAILABLE' });
  assert.equal(r.stage, 'done', JSON.stringify(r));
  assert.ok(w.root.state.v4.retired.g2 && !w.root.state.v4.disqualified.g2);
});

test('WITHDRAWAL needs the member\'s own signature; ordinary rotation needs the owner governance quorum + the outgoing guardian', async () => {
  const w = buildV4();
  deny((await openGov(w, { accused: ['g3'], ground: 'WITHDRAWAL', evidence: [{ ...w.owner.withdrawal('g2'), subjectId: 'g3' }] })).r, 'WITHDRAWAL_SIGNATURE');
  assert.equal((await emergencyReplace(w, { accused: ['g3'], ground: 'WITHDRAWAL' })).stage, 'done');
  const rep = w.owner.newParticipant('guardian', 'g-rot', 'holder-rot', '-');
  deny(await w.ownerAct('GUARDIAN_ROTATE', { guardianId: 'g1', replacement: rep, ground: 'ROTATION' }, ['k1-phone', 'k2-laptop', 'k3-root-hw']), 'ATTESTATION|WITHDRAWAL');
  deny(await w.ownerAct('GUARDIAN_ROTATE', { guardianId: 'g1', replacement: rep, ground: 'ROTATION' }, ['k1-phone', 'k3-root-hw'], { attestation: (a) => ({ withdrawalSig: w.owner.withdrawalSign(a, 'g1') }) }), 'QUORUM_NOT_SATISFIED');
  ok(await w.ownerAct('GUARDIAN_ROTATE', { guardianId: 'g1', replacement: rep, ground: 'ROTATION' }, ['k1-phone', 'k2-laptop', 'k3-root-hw'], { attestation: (a) => ({ withdrawalSig: w.owner.withdrawalSign(a, 'g1') }) }));
  assert.equal(w.root.state.guardians['g-rot'].status, 'active');
});

test('SECURITY DELAY + CANCELLATION: no execution before 24 h; the owner (ORC or quorum) can cancel during the delay; notifications required', async () => {
  const w = buildV4();
  ok((await openGov(w, { accused: ['g1'] })).r);
  assert.equal(gc(w).dispatched.length, 3, 'every channel notified');
  for (const v of gc(w).electorate) ok(await govVote(w, v));
  ok(await govTally(w)); assert.equal(gc(w).state, 'APPROVED');
  deny(await w.recovery.tryGovExecute(w.root.state), 'GOV_SECURITY_DELAY_OPEN|GOV_EXPIRE|GOV_NOT_EXPIRED');
  ok(await w.submitRaw('GOV_CASE_CANCEL', { gcaseId: gc(w).gcaseId, gcaseDigest: gc(w).digest }, { approvals: (a) => w.owner.authorize(w.root.state, a, ['orc-1']) }));
  assert.equal(w.root.state.v4.gcaseHistory.at(-1).outcome, 'CANCELLED'); assert.equal(w.root.state.guardians.g1.status, 'active');
});

test('MUTUAL EXCLUSION: no governance case during a recovery case and vice versa; vote window expiry closes the case', async () => {
  const { openCaseV4 } = await import('../../src/v4/recovery/sim.mjs');
  const w = buildV4();
  ok((await openCaseV4(w, { lost: ['k2-laptop'] })).r);
  deny((await openGov(w, { accused: ['g1'] })).r, 'RECOVERY_CASE_OPEN');
  const w2 = buildV4();
  ok((await openGov(w2, { accused: ['g1'] })).r);
  deny((await openCaseV4(w2, { lost: ['k2-laptop'] })).r, 'GOVERNANCE_CASE_OPEN');
  await w2.advance(73 * H, 6 * H);
  ok(await w2.recovery.tryGovExecute(w2.root.state));
  assert.equal(w2.root.state.v4.gcaseHistory.at(-1).outcome, 'EXPIRED');
});

test('ATTACKER (stolen K1, compromised g1+g2, one bribed adjudicator) cannot replace the honest guardian g3', async () => {
  const w = buildV4();
  deny((await openGov(w, { accused: ['g3'], owners: ['k1-phone'] })).r, 'EMERGENCY_OWNER_QUORUM');
  deny((await openGov(w, { accused: ['g3'], owners: ['k1-phone', 'k2-laptop'] })).r, 'EMERGENCY_OWNER_QUORUM');
  // even with an owner quorum (residual: two owner roles stolen) a single bribed adjudicator proves nothing
  deny((await openGov(w, { accused: ['g3'], owners: ['k1-phone', 'k3-root-hw'], adj: ['adj-1'] })).r, 'ACCUSATION_NOT_ESTABLISHED');
  assert.equal((await w.verify()).takeovers.length, 0);
});
