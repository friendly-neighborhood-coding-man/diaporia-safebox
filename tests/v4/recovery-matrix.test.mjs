// All 32 loss subsets + named scenarios (mission §12). Success is never "reached a new Epoch": the final active set must
// equal the owner's approved replacement set, Purpose and assets preserved, old authorizations dead, verifier clean.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runSubset, subsets, expectedOutcome, SCENARIOS } from '../../src/v4/recovery/matrix.mjs';

for (const lost of subsets()) {
  test(`matrix: lost {${lost.join(',') || 'none'}}`, async () => {
    const r = await runSubset(lost);
    assert.equal(r.outcome, expectedOutcome(lost.length), JSON.stringify(r));
    assert.equal(r.Q2_attackerDenied, true, 'R-1 collusion denied: ' + r.attackerStoppedBy);
    assert.equal(r.purposePreserved, true); assert.equal(r.assetsPreserved, true); assert.equal(r.verifierClean, true);
    assert.equal(r.lockdownAfter, false, 'no perpetual lockdown');
    if (['RECOVERED', 'NEW_EPOCH'].includes(r.outcome)) {
      assert.equal(r.finalAuthorityMatchesApprovedSet, true); assert.equal(r.postRecoveryPayment, true); assert.equal(r.Q7_oldAuthorizationsInvalid, true);
    }
    if (r.outcome === 'RECOVERED' && r.Q4_survivorPaymentDuringCase !== null) assert.equal(r.Q4_survivorPaymentDuringCase, true, 'minority loss: payments continue');
    if (r.outcome === 'NEW_EPOCH') assert.equal(r.Q3_lockdown, true, 'majority loss: protective lockdown during the case');
  });
}

test('matrix scenarios', async () => {
  const s = {}; for (const [k, f] of Object.entries(SCENARIOS)) s[k.split(':')[0].split(' (')[0]] = await f();
  const get = (p) => Object.entries(s).find(([k]) => k.startsWith(p))[1];
  assert.equal(get('stolen DAILY').Q2, true);
  assert.equal(get('compromised Guardians').Q1, true); assert.equal(get('compromised Guardians').Q2, true);
  assert.equal(get('compromised identity').Q1, true);
  assert.equal(get('compromised notification').Q1, true);
  assert.equal(get('false accusation').Q2, true);
  assert.equal(get('genuine identity dispute').Q1, true);
  assert.equal(get('legitimate owner silence').Q2, true);
  assert.equal(get('device replacement').Q1, true);
  assert.equal(get('signed cancellation').Q4_paymentAfter, true);
  assert.ok(get('repeated reconstitution').attempts.includes('RECOVERY_CLAIM_BUDGET_EXHAUSTED'));
  assert.ok(get('repeated reconstitution').lockdownHoursTotal <= 96 + 73);
  const ne = get('new-Epoch'); assert.equal(ne.Q1, true); assert.equal(ne.Q7, true); assert.equal(ne.authoritySet, true);
});
