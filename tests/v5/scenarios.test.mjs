// Mission §14 Scenarios A–E as regression tests (deterministic simulation; MOCK ledger and email).
import test from 'node:test';
import assert from 'node:assert/strict';
import { scenarioA, scenarioB, scenarioC, scenarioD, scenarioE } from '../../src/v5/sim/scenarios.mjs';
import { runDatasets } from '../../src/v5/sim/datasets.mjs';

test('Scenario A: stolen DAILY key burst is detected, delayed, notified; attacker cannot self-approve or expand; owner responds', async () => {
  const r = await scenarioA();
  assert.ok(r.metrics.timeToDetectionMs <= 60_000);
  assert.equal(r.metrics.settledBeforeDetection, 0);
  assert.equal(r.metrics.attackerBudgetLossYocto, '0');
  assert.ok(r.notifications.mockSent >= 1);
  assert.match(r.attackerActions.rapidSelfVote, /RAPID_FACTOR_IS_AFFECTED_CREDENTIAL/);
  assert.match(r.attackerActions.rapidActivate, /RAPID_QUORUM_NOT_MET/);
  assert.match(r.attackerActions.payAttackerAccount, /RECIPIENT_NOT_IN_PURPOSE/);
  assert.match(r.attackerActions.amendPurpose, /QUORUM_NOT_SATISFIED/);
  assert.match(r.attackerActions.releaseOwnDelay, /INCIDENT_REVIEW_BY_AFFECTED_CREDENTIAL/);
  assert.deepEqual(r.owner, { quarantine: 'OK', fraudReview: 'OK', revoke: 'OK' });
  assert.equal(r.metrics.ownerPaymentAfter, 'OK');
  assert.equal(r.verifier.ok, true);
});

for (const multiOwner of [false, true]) test(`Scenario B${multiOwner ? ' (multi-owner)' : ''}: genuine urgent spending completes under Rapid-Use, owner ends it, protection resumes`, async () => {
  const r = await scenarioB({ multiOwner });
  assert.deepEqual([r.steps.request, ...r.steps.votes, r.steps.activate, r.steps.end], ['OK', 'OK', 'OK', 'OK', 'OK']);
  assert.equal(r.metrics.completionRate, 1);
  assert.ok(r.metrics.acceleratedByRapid >= 1);
  assert.ok(r.metrics.afterEndAnomaly.every(x => x === 'ANOMALY_PAYMENT_DELAY'));
  assert.equal(r.verifier.ok, true);
  assert.ok(r.verifier.rapidGrants.every(g => Number(g.expiresAt) - Number(g.activatedAt) <= 24 * 3600_000));
});

test('Scenario C: evasive strategies', async () => {
  const { cases: c } = await scenarioC();
  for (const [k, v] of Object.entries(c)) assert.equal(v.verifier, true, k);
  assert.ok(c.split_small_payments.k1.delayed > 0);
  assert.ok(c.across_all_merchants.k1.delayed > 0);
  assert.ok(c.slow_baseline_poisoning.k1.delayed >= 10);
  assert.equal(c.false_alarm_against_other_key.otherKeyAnomaly, 'NONE');
  assert.ok(c.notification_flood.notify.byState.DELIVERED <= 2);
  assert.match(c.forged_votes.forgedCredId, /CHALLENGE_NOT_FOR_THIS_CREDENTIAL/);
  assert.match(c.replay_prior_authorization.replaySame, /ACTION_REPLAY/);
  assert.match(c.replay_prior_authorization.activateRq2, /RAPID_QUORUM_NOT_MET/);
  assert.equal(c.rapid_after_revocation.grant, 'ENDED_EPOCH_CHANGE');
  assert.equal(c.switch_epoch_or_purpose.grant, 'ENDED_EPOCH_CHANGE');
  assert.equal(c.continue_after_expiry.grant, 'EXPIRED');
  assert.ok(c.continue_after_expiry.after.includes('ANOMALY_PAYMENT_DELAY'));
  assert.equal(c.exhaust_emergency_resources.ownerStillCanRequest, 'OK');
});

test('Scenario D: no unauthorized Rapid-Use activation, attempts audited and bounded, owner path intact', async () => {
  const r = await scenarioD();
  assert.equal(r.unauthorizedActivations, 0);
  assert.ok(r.resultCodes.RAPID_REQUEST_RATE_LIMIT > 0);
  assert.deepEqual(r.ownerPath, { request: 'OK', orc: 'OK', k3: 'OK', activate: 'OK' });
  assert.match(r.multi.k2SameHuman, /RAPID_DUPLICATE_PRINCIPAL_VOTE/);
  assert.match(r.multi.activate, /RAPID_QUORUM_NOT_MET/);
  assert.equal(r.verifier.ok, true);
});

test('Scenario E: compromised notification infrastructure never authorizes anything', async () => {
  const r = await scenarioE();
  assert.ok(r.cases.outage.delayedPaymentsStillDelayed >= 3, 'an outage grants no exception');
  assert.deepEqual(r.cases.content, { links: false, memoLeaked: false, statesNoApproval: true });
  assert.match(r.cases.stolenMailbox.reviewWithEmailToken, /UNEXPECTED_EVIDENCE/);
  assert.match(r.cases.stolenMailbox.activateWithEmail, /UNEXPECTED_EVIDENCE|COMMAND_APPROVAL_FIELDS/);
  assert.deepEqual(Object.values(r.cases.injectedContent).slice(1), [true, true, true]);
  assert.equal(r.metrics.accelerationsWithoutAuthenticator, 0);
  assert.equal(r.verifier.ok, true);
});

test('labelled trajectories (dev set, seed 1): no benign delay, every malicious trajectory detected', async () => {
  const { summary } = await runDatasets({ seeds: [1] });
  assert.equal(summary.falsePositives, 0);
  assert.equal(summary.truePositiveRate, 1);
});
