// Every combination of 0..5 lost personal credentials (32 cases): the legitimate owner's outcome, latency, and the
// post-recovery invariants (old credentials dead, purpose and assets preserved, new keys operate, verifier clean).
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync } from 'node:fs';
import { buildV3 } from '../../src/v3/world.mjs';
import { legitimateRecovery } from '../../src/v3/recovery/sim.mjs';

const KEYS = ['k1-phone', 'k2-laptop', 'k3-root-hw', 'k4-freeze', 'k5-recovery-hw'];
const Y = (c) => (BigInt(c) * 10n ** 22n).toString();
const rows = [];

for (let mask = 0; mask < 32; mask++) {
  const lost = KEYS.filter((_, i) => mask & (1 << i));
  test(`lost {${lost.join(',') || 'none'}}`, async () => {
    const w = buildV3();
    const before = { purpose: w.root.state.purposeDigest, balances: await w.ledgerRead.call('BALANCES', {}) };
    for (const k of lost) w.owner.dev(k).lost = true;
    let res;
    if (!lost.length) res = { outcome: 'NO_RECOVERY_NEEDED', latencyMs: 0, interventions: 0 };
    else res = await legitimateRecovery(w, lost);
    const expected = lost.length === 0 ? 'NO_RECOVERY_NEEDED' : lost.length <= 2 ? 'RECOVERED' : lost.length <= 4 ? 'NEW_EPOCH' : 'RECOVERY_IMPOSSIBLE';
    assert.equal(res.outcome, expected, JSON.stringify(res).slice(0, 600));
    const st = w.root.state;
    assert.equal(st.purposeDigest, before.purpose, 'purpose preserved');
    assert.deepEqual(await w.ledgerRead.call('BALANCES', {}), before.balances, 'assets preserved (no movement during recovery)');
    let payOk = null;
    if (expected === 'RECOVERED' || expected === 'NEW_EPOCH') {
      assert.equal(st.lockdown.active, false);
      for (const k of lost) assert.notEqual(st.creds[k].status, 'active', 'lost credential retired');
      if (expected === 'NEW_EPOCH') for (const k of KEYS) assert.equal(st.creds[k].status, 'retired', 'old environment retired');
      // an old credential's capability or approval never works again
      const oldDaily = lost.find(k => k.startsWith('k1') || k.startsWith('k2'));
      if (oldDaily) assert.equal((await w.pay({ credId: oldDaily, amountYocto: Y(1) })).ok, false);
      const daily = Object.values(st.creds).find(c => c.status === 'active' && c.role === 'DAILY');
      const r = await w.pay({ credId: daily.credId, amountYocto: Y(1) });
      payOk = r.ok; assert.equal(r.ok, true, JSON.stringify(r.error));
      await w.advance(11 * 60_000);
      const v = await w.verify();
      assert.equal(v.chainValid, true); assert.equal(v.financial.violations.length, 0); assert.equal(v.takeovers.length, 0);
    }
    if (expected === 'RECOVERY_IMPOSSIBLE') {
      assert.equal(st.lockdown.active, true, 'assets stay locked, never released to anyone');
      assert.equal((await w.pay({ credId: 'k1-phone', amountYocto: Y(1) })).ok, false);
    }
    rows.push({ lost: lost.join('+') || 'none', n: lost.length, outcome: res.outcome, latencyH: +(res.latencyMs / 3600_000).toFixed(2), interventions: res.interventions, postRecoveryPayment: payOk, epoch: st.epoch });
  });
}

test.after(() => {
  if (process.env.SAFEBOX_WRITE_EVIDENCE) { mkdirSync('docs/evidence/v3', { recursive: true }); writeFileSync('docs/evidence/v3/recovery-combinations.json', JSON.stringify(rows.sort((a, b) => a.n - b.n || a.lost.localeCompare(b.lost)), null, 1) + '\n'); }
});
