// V5.1 independent-verifier repairs (findings F1, F3, F4, F6 of the V5.1 independent verification).
// Each test simulates a COMPROMISED vault that rewrites its own records; the verifier must still flag the effect from
// signed evidence (owner / delegate signatures) and the engine's own append-only RISK journal.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, H, D, Y, near, burst } from './helpers.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';

const MIN = 60_000;
const codes = (v) => v.financial.violations.flatMap(x => x.codes);
function warm(policy = 'EXP_30') {
  const w = buildV5({ config5: { bufferPolicy: policy } });
  w.clock.advance(10 * H); w.wall.t += 1;
  const now = w.now(); const rows = [];
  for (let d = 30; d >= 4; d--) for (const cred of ['k1-phone', 'k2-laptop']) for (const h of [0, 5]) rows.push({ credId: cred, recipient: 'merchant-a.mock', amount: near(0.02), at: now - d * D + h * H });
  w.vault.seedHistory(rows);
  return w;
}
const pay = async (w, o = {}) => { const r = ok(await w.pay(o)); return w.vault.v5payments().find(p => p.payment_id === r.paymentId); };

test('F1: clearing the vault\'s incident_id / flow / risk_class does not hide a HIGH payment settled without resolution', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN });
  assert.ok(w.vault.v5payments().some(p => p.risk_class === 'HIGH'));
  w.vault.store.db.prepare("UPDATE v5_pay SET risk_class='LOW', incident_id=NULL, flow='cred:someone-else', cred_id='someone-else'").run();
  await w.advance(25 * H, 15 * MIN);
  assert.ok(w.vault.v5payments().some(p => p.state === 'SETTLED'));
  assert.ok(codes(await verifyWorld(w)).includes('HIGH_RISK_SETTLED_WITHOUT_RESOLUTION'));
});

test('F1 control: an honest HIGH incident resolved LEGITIMATE by a trusted key verifies clean', async () => {
  const w = buildV5();
  await burst(w, 8, { step: MIN });
  const inc = w.vault.incidents()[0].incident_id;
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: inc, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw']));
  await w.advance(30 * MIN);
  const v = await verifyWorld(w);
  assert.ok(w.vault.v5payments().filter(p => p.state === 'SETTLED').length >= 1);
  assert.equal(v.ok, true, JSON.stringify(codes(v)));
});

test('F3: an effect whose V5 record was deleted, or whose proposal time was rewritten, is flagged', async () => {
  const w = warm();
  const p = await pay(w, { amountYocto: near(0.05) });
  assert.ok(p.buffer_ms > 30_000);
  w.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(p.proposed_at + 30_000, p.payment_id);
  await w.advance(2 * MIN, 10_000);
  w.vault.store.db.exec('DROP TRIGGER v5_pay_no_delete'); // a compromised vault can drop its own guard
  w.vault.store.db.prepare('DELETE FROM v5_pay WHERE payment_id=?').run(p.payment_id);
  const c = codes(await verifyWorld(w));
  assert.ok(c.includes('EFFECT_WITHOUT_V5_EVALUATION_RECORD') && c.includes('BUFFER_BYPASSED'), JSON.stringify(c));
  const w2 = warm();
  const q = await pay(w2, { amountYocto: near(0.05) });
  w2.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(q.proposed_at + 30_000, q.payment_id);
  await w2.advance(2 * MIN, 10_000);
  w2.vault.store.db.prepare('UPDATE v5_pay SET proposed_at=proposed_at-? WHERE payment_id=?').run(q.buffer_ms, q.payment_id); // hide the early release
  const c2 = codes(await verifyWorld(w2));
  assert.ok(c2.includes('PROPOSAL_TIME_MISMATCH') && c2.includes('BUFFER_BYPASSED'), JSON.stringify(c2));
});

test('F4: rewriting the vault\'s flow column does not hide a tier reset (flows come from signed evidence)', async () => {
  const w = warm();
  await pay(w, { amountYocto: near(0.005) }); await w.advance(MIN, MIN);
  const p2 = await pay(w, { amountYocto: near(0.005) }); assert.ok(Number(p2.tier) >= 1);
  await w.advance(11 * MIN, MIN);
  w.vault.store.db.prepare('UPDATE v5_pay SET tier=0').run();
  const q = await pay(w, { amountYocto: near(0.005) });
  assert.ok(Number(q.tier) < Number(p2.tier));
  w.vault.store.db.prepare("UPDATE v5_pay SET flow='cred:other' WHERE payment_id<>?").run(q.payment_id);
  const v = await verifyWorld(w);
  assert.ok(v.buffer.tierResets >= 1 && codes(v).includes('BUFFER_TIER_RESET'), JSON.stringify(codes(v)));
});

test('F6: a delegated op accepted long after its signed issuedAt is flagged (DELEGATED_OP_STALE_AT_PROPOSAL)', async () => {
  const w = buildV5();
  const k = w.owner.newDelegate('d1');
  ok(await w.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w.iso(w.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  const { op, sig } = w.delegateOp('d1', 1, { amountYocto: Y(1) });
  await w.advance(15 * MIN);
  // a compromised vault skips its own freshness check (simulated by a vault clock that lags the real one)
  const real = w.vault.now; const lag = w.now() - 15 * MIN; w.vault.now = () => lag;
  try { w.vault.proposeDelegated({ op, sig }); } finally { w.vault.now = real; }
  await w.advance(15 * MIN, MIN);
  const c = codes(await verifyWorld(w));
  assert.ok(c.includes('DELEGATED_OP_STALE_AT_PROPOSAL'), JSON.stringify(c));
  // control: a fresh op verifies without the stale code
  const w2 = buildV5(); const k2 = w2.owner.newDelegate('d1');
  ok(await w2.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k2.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w2.iso(w2.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  await w2.payDelegated('d1', 1, { amountYocto: Y(1) });
  await w2.advance(15 * MIN, MIN);
  assert.ok(!codes(await verifyWorld(w2)).includes('DELEGATED_OP_STALE_AT_PROPOSAL'));
});
