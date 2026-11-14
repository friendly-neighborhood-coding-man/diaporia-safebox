// V6 hardening P0.2 (payment display): summaryDigest in the owner-signed binding must be the digest of the canonical
// Root-derived summary. Attack: a compromised display layer shows the owner a different amount/recipient/epoch than the
// capability pays, and records the digest of what it showed. bf7403d never recomputed summaryDigest (display-only).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV6, Y, deny, ok } from './helpers6.mjs';
import { paymentSummary, summaryDigestOf } from '../../src/v6/vault/payment-approval.mjs';
import { projectState } from '../../src/v5/root/chain.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';

const shown = (w, b, patch) => summaryDigestOf(paymentSummary(projectState(w.root.state, w.now()), { ...b, ...patch }, { memo: null }));
const cases = [
  ['displayed amount 1 instead of 3', (w) => ({ amountYocto: Y(1) })],
  ['displayed another recipient', () => ({ recipientId: 'merchant-b.mock' })],
  ['displayed a later approval expiry', () => ({ approvalExpiresAt: '2099-01-01T00:00:00.000Z' })],
  ['displayed weaker assurance', () => ({ assurance: 'UV' })],
  ['arbitrary digest', null],
];
for (const [name, patch] of cases) {
  test(`P0.2-summary: an approval whose summaryDigest is not the canonical Root summary is refused (${name})`, async () => {
    const w = buildV6({ fingerprintOnly: ['k2-laptop'] });
    const r = await w.pay({ credId: 'k2-laptop', amountYocto: Y(3), tamper: (b) => { b.summaryDigest = patch ? shown(w, b, patch(w)) : 'ab'.repeat(32); } });
    deny(r, 'V6_SUMMARY_NOT_CANONICAL');
    assert.equal(w.vault.v5payments().length, 0);
  });
}
test('P0.2-summary: the honest summary (with the untrusted requester note shown) still verifies at the Vault and the verifier', async () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'] });
  ok(await w.pay({ credId: 'k2-laptop', amountYocto: Y(3), memo: 'order 42 - please approve quickly' }));
  assert.ok(w.lastApproval.summary.some((l) => l.includes('UNTRUSTED')), 'the device still shows the requester note');
  await w.advance(12 * 60_000);
  const v = await verifyWorld6(w); assert.equal(v.ok, true, JSON.stringify(v.v6));
});
