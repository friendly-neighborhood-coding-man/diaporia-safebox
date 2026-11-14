// V5.1 P4: adaptive exponential settlement buffer (EXPERIMENTAL candidate EXP_30) vs fixed 600 s (FIXED_600).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, D, Y, near, burst, rapidRequest, rapidVote, rapidActivate } from './helpers.mjs';
import { tierFromInputs, tierToBufferMs, bufferFloorMs } from '../../src/v5/risk/buffer.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';
import { genesisState } from '../../src/v5/root/chain.mjs';
import { OwnerWorldV5 } from '../../src/v5/kit.mjs';
import { T0 } from '../../src/v5/world.mjs';
import { ExecutionVault } from '../../src/v3/vault/vault.mjs';

const MIN = 60_000;
const codes = (v) => v.financial.violations.flatMap(x => x.codes);
const base = { flowValue1hBps: '0', dailyUseBps: '0', cumulativeUseBps: '0', count10m: '1', count1h: '1', coldStart: 'false', baselineDeviation: 'false', securityCorrelated: 'false', openIncident: 'false', detectorLevel: 'NONE', stickyTier: '0' };
/** EXP_30 world with 27 days of clean history at 10:00 and 15:00 UTC, clock moved to 10:00 UTC (a usual hour). */
function warm(policy = 'EXP_30') {
  const w = buildV5({ config5: { bufferPolicy: policy } });
  w.clock.advance(10 * H); w.wall.t += 1;
  const now = w.now(); const rows = [];
  for (let d = 30; d >= 4; d--) for (const cred of ['k1-phone', 'k2-laptop']) for (const h of [0, 5]) rows.push({ credId: cred, recipient: 'merchant-a.mock', amount: near(0.02), at: now - d * D + h * H });
  w.vault.seedHistory(rows);
  return w;
}
const pay = async (w, o = {}) => { const r = ok(await w.pay(o)); return w.vault.v5payments().find(p => p.payment_id === r.paymentId); };
const stmt = (p) => JSON.parse(p.decision).statement;

test('P4: bufferSeconds(n) = min(600, 30 * 2^n): 30, 60, 120, 240, 480, 600, 600; FIXED_600 is always 600 s', () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 12].map(n => tierToBufferMs('EXP_30', n) / 1000), [30, 60, 120, 240, 480, 600, 600, 600]);
  assert.equal(tierToBufferMs('EXP_30', 'x'), 600_000, 'malformed tier fails safe');
  assert.equal(tierToBufferMs('EXP_30', -1), 600_000);
  for (const n of [0, 3, 9]) assert.equal(tierToBufferMs('FIXED_600', n), 600_000);
  assert.equal(bufferFloorMs('EXP_30'), 30_000); assert.equal(bufferFloorMs('FIXED_600'), 600_000);
});

test('P4: the tier is a deterministic bounded function of the signed inputs; each input moves it; sticky floor; cap 5', () => {
  assert.equal(tierFromInputs(base), 0);
  const t = (o) => tierFromInputs({ ...base, ...o });
  assert.equal(t({ flowValue1hBps: '5000' }), 1); assert.equal(t({ flowValue1hBps: '10000' }), 2); assert.equal(t({ flowValue1hBps: '30000' }), 3);
  assert.equal(t({ dailyUseBps: '2500' }), 1); assert.equal(t({ dailyUseBps: '5000' }), 2);
  assert.equal(t({ cumulativeUseBps: '5000' }), 1);
  assert.equal(t({ count10m: '2' }), 1); assert.equal(t({ count1h: '4' }), 1);
  assert.equal(t({ coldStart: 'true' }), 1); assert.equal(t({ baselineDeviation: 'true' }), 1);
  assert.equal(t({ securityCorrelated: 'true' }), 2); assert.equal(t({ openIncident: 'true' }), 3);
  assert.equal(t({ detectorLevel: 'WATCH' }), 1); assert.equal(t({ detectorLevel: 'DELAY' }), 2);
  assert.equal(t({ stickyTier: '4' }), 4, 'never below the flow\'s highest tier in the last hour');
  assert.equal(t({ openIncident: 'true', securityCorrelated: 'true', detectorLevel: 'DELAY' }), 5, 'clamped at 5');
  assert.equal(tierFromInputs(null), 5); assert.equal(t({ count10m: 'NaN', stickyTier: 'NaN' }), 0);
  for (let i = 0; i < 3; i++) assert.equal(t({ flowValue1hBps: '10000', count10m: '2' }), 3, 'same inputs, same tier');
});

test('P4: bufferPolicy is owner-signed in the genesis extension; unknown policy refused; vault floor must match it', () => {
  const o = new OwnerWorldV5({ t0: T0, config5: { bufferPolicy: 'EXP_1' } });
  assert.throws(() => genesisState(o.genesis5(), { pinnedChainId: o.chainId5 }), /V5_CONFIG_BUFFER_POLICY/);
  const w = buildV5({ config5: { bufferPolicy: 'EXP_30' } });
  assert.equal(w.root.state.v5.config.bufferPolicy, 'EXP_30');
  assert.equal(w.vault.cfg.minBufferMs, 30_000);
  const w2 = buildV5();
  assert.equal(w2.root.state.v5.config.bufferPolicy, 'FIXED_600', 'default policy = V5 fixed buffer');
});

test('P4: under EXP_30 a usual, low-value payment from verified history waits 30 s and settles; FIXED_600 waits 600 s', async () => {
  for (const [policy, expect] of [['EXP_30', 30_000], ['FIXED_600', 600_000]]) {
    const w = warm(policy);
    const p = await pay(w, { amountYocto: near(0.01) });
    assert.equal(p.buffer_ms, expect, policy + ' ' + JSON.stringify(stmt(p).tierInputs));
    assert.equal(p.release_at - p.proposed_at, expect);
    await w.advance(expect - 1000, 1000);
    assert.equal(w.vault.v5payments().find(x => x.payment_id === p.payment_id).state, 'BUFFERED', 'not before the buffer');
    await w.advance(2 * MIN, 1000);
    assert.equal(w.vault.v5payments().find(x => x.payment_id === p.payment_id).state, 'SETTLED');
    assert.equal((await verifyWorld(w)).ok, true);
  }
});

test('P4: splitting a maximum payment into 10 small ones does not lower the tier below the single large payment', async () => {
  const a = warm(); const big = await pay(a, { amountYocto: Y(6) });
  const b = warm(); const tiers = [];
  for (let i = 0; i < 10; i++) { const p = await pay(b, { amountYocto: near(0.006) }); tiers.push(Number(p.tier)); await b.advance(12_000, 12_000); }
  assert.ok(tiers.every((t, i) => i === 0 || t >= tiers[i - 1]), 'tiers never decrease inside the hour: ' + tiers);
  assert.ok(Math.max(...tiers.slice(-3)) >= Number(big.tier), `split ${tiers} vs single ${big.tier}`);
  const v = await verifyWorld(b); assert.equal(v.buffer.tierResets, 0);
});

test('P4: verifier recomputes the tier, checks the signature and flags a payment released before its signed buffer', async () => {
  const w = warm();
  const p = await pay(w, { amountYocto: near(0.05) });
  assert.ok(p.buffer_ms > 30_000);
  w.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(p.proposed_at + 30_000, p.payment_id);
  await w.advance(2 * MIN, 10_000);
  const v = await verifyWorld(w);
  assert.ok(codes(v).includes('BUFFER_BYPASSED'), JSON.stringify(codes(v)));
  // forged tier in the vault record (signature no longer matches)
  const w2 = warm(); const q = await pay(w2, { amountYocto: near(0.05) });
  const d = JSON.parse(q.decision); d.statement.tier = '0'; d.statement.bufferMs = '30000';
  w2.vault.store.db.prepare('UPDATE v5_pay SET decision=? WHERE payment_id=?').run(JSON.stringify(d), q.payment_id);
  w2.vault.store.db.prepare('UPDATE payments SET release_at=? WHERE payment_id=?').run(q.proposed_at + 30_000, q.payment_id);
  await w2.advance(2 * MIN, 10_000);
  assert.ok(codes(await verifyWorld(w2)).some(c => c === 'BUFFER_DECISION_INVALID' || c === 'BUFFER_BYPASSED'));
});

test('P4: a compromised vault that lowers stored tiers to reset the next decision is exposed (BUFFER_TIER_RESET)', async () => {
  const c = warm(); // control: honest vault keeps the sticky tier
  await pay(c, { amountYocto: near(0.005) }); await c.advance(MIN, MIN); const c2 = await pay(c, { amountYocto: near(0.005) }); await c.advance(11 * MIN, MIN);
  assert.equal((await pay(c, { amountYocto: near(0.005) })).tier, c2.tier);
  assert.equal((await verifyWorld(c)).buffer.tierResets, 0);
  const w = warm();
  // two quick payments: the second earns a tier from the 10-minute frequency; 11 min later only stickiness keeps it
  await pay(w, { amountYocto: near(0.005) }); await w.advance(MIN, MIN);
  const p2 = await pay(w, { amountYocto: near(0.005) }); assert.ok(Number(p2.tier) >= 1);
  await w.advance(11 * MIN, MIN);
  w.vault.store.db.prepare('UPDATE v5_pay SET tier=0').run();
  const q = await pay(w, { amountYocto: near(0.005) });
  assert.ok(Number(q.tier) < Number(p2.tier), 'the tampered history lowered the next signed tier');
  assert.equal(stmt(q).tierInputs.stickyTier, '0');
  const v = await verifyWorld(w);
  assert.ok(v.buffer.tierResets >= 1);
  assert.ok(codes(v).includes('BUFFER_TIER_RESET'));
});

test('P4: Rapid-Use removes only the anomaly delay, never the signed buffer; HIGH unresolved never auto-releases at max buffer', async () => {
  const w = warm();
  await burst(w, 6, { amountYocto: near(0.03) });
  assert.ok(w.vault.v5payments().some(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY'));
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw')); ok(await rapidActivate(w));
  await w.advance(15 * MIN, 10_000);
  const acc = w.vault.v5payments().filter(p => p.anomaly === 'RELEASED_BY_RAPID');
  assert.ok(acc.length >= 1);
  for (const p of acc) assert.ok(p.settled_at - p.proposed_at >= p.buffer_ms, 'buffer kept');
  const h = warm();
  await burst(h, 8, { step: MIN });
  assert.ok(h.vault.v5payments().some(p => p.risk_class === 'HIGH'));
  await h.advance(26 * H, 15 * MIN);
  assert.equal(h.vault.v5payments().filter(p => p.risk_class === 'HIGH' && p.state === 'SETTLED').length, 0);
});

test('P4: restart safety: a payment reserved but never evaluated (crash between V3 and V5 steps) gets the maximum buffer', async () => {
  const w = warm();
  const pc = w.owner.paycap(w.view(), { credId: 'k2-laptop', recipientId: 'merchant-a.mock', amountYocto: Y(1) });
  const r = ExecutionVault.prototype.propose.call(w.vault, { capability: pc.capability, approval: pc.approval, recipientId: 'merchant-a.mock', amountYocto: Y(1), asset: 'NEAR', memo: 'x' });
  assert.equal(w.vault.store.get(r.paymentId).release_at - w.now(), 30_000, 'V3 core alone would release at the 30 s floor');
  w.restartVault();
  assert.equal(w.vault.store.get(r.paymentId).release_at - w.vault.store.get(r.paymentId).proposed_at, 600_000);
});
