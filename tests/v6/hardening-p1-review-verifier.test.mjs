// Final independent review of 1569fc6 (MEDIUM, reviewer's reproducer kept verbatim in substance): a dishonest Vault under
// LEGACY_V5 settles a fingerprint-only credential's payment with no V6 approval; the independent V6 verifier must flag it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV6 } from './helpers6.mjs';
import { verifyWorld6 } from '../../src/v6/supervisor/verifier.mjs';
import { Y } from './helpers6.mjs';
const LEG5 = { payment: { mode: 'LEGACY_V5', approvalTtlMs: String(5 * 60_000) } };
const H = 3600_000;
for (const fingerprintAssurance of ['LOCAL_GATE', 'HIGH_ASSURANCE']) test(`verifier vs dishonest LEGACY_V5 vault (${fingerprintAssurance})`, async () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], policy6: { ...LEG5, fingerprintAssurance } });
  // dishonest vault: drop both halves of the P0.1 LEGACY fix
  w.vault.policy6 = ((orig) => () => ({ ...orig(), fingerprintOnlyCreds: [] }))(w.vault.policy6.bind(w.vault));
  const r = await w.v5pay({ credId: 'k2-laptop', amountYocto: Y(1) });
  assert.equal(r.ok, true, JSON.stringify(r.error));
  await w.advance(30 * H, 15 * 60_000);
  const p = w.vault.v5payments().at(-1); 
  const v = await verifyWorld6(w);
  const codes = [...v.financial.violations.flatMap(x => x.codes), ...v.v6.ownerApprovals.violations.flatMap(x => x.codes)];

  assert.equal(p.state, 'SETTLED');
  assert.ok(!v.ok, 'GAP: verifier accepts a settled fingerprint-only payment without V6 approval');
});
test('honest LEGACY_V5 vault: a fingerprint-only payment through the V6 ceremony settles and the verifier accepts it', async () => {
  const w = buildV6({ fingerprintOnly: ['k2-laptop'], policy6: LEG5 });
  const r = await w.pay({ credId: 'k2-laptop', amountYocto: Y(1) }); assert.equal(r.ok, true, JSON.stringify(r.error));
  await w.advance(30 * H, 15 * 60_000);
  const v = await verifyWorld6(w);
  assert.equal(v.ok, true, JSON.stringify(v.v6?.ownerApprovals ?? v).slice(0, 300));
  assert.equal(v.v6.ownerApprovals.checked, 1);
});
