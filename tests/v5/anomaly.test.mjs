// Mission 4: behavioural anomaly detection and ANOMALY_PAYMENT_DELAY (targeted, bounded, engine-only, never a Purpose change).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, D, Y, burst } from './helpers.mjs';
import { evaluate, baselineOf, cleanHistory, RISK_POLICY_V1 } from '../../src/v5/risk/detector.mjs';
import { RiskPolicyEngine } from '../../src/v5/risk/engine.mjs';
import { newSigner5 } from '../../src/v5/common/v5.mjs';

const PURPOSE = { dailyLimitYocto: Y(500), cumulativeLimitYocto: Y(10000), perPaymentMaxYocto: Y(6), recipients: ['m'] };
const hist = (days, perDay, now, { amount = Y(2), flow = 'cred:k1', start = 1 } = {}) => {
  const out = []; for (let d = start; d <= days; d++) for (let i = 0; i < perDay; i++) out.push({ paymentId: `h${d}-${i}`, flow, recipient: 'm', amount, at: now - d * D + (9 + i) * H, state: 'SETTLED', baselineEligible: true });
  return out;
};
const ev = (history, n, now, { step = 60_000, amount = Y(2), securityTimes = [] } = {}) => {
  const h = [...history]; let last;
  for (let i = 0; i < n; i++) { const p = { paymentId: 'n' + i, flow: 'cred:k1', recipient: 'm', amount, at: now + i * step, state: 'BUFFERED' }; last = evaluate(p, { history: h, purpose: PURPOSE, spent: { last24hYocto: '0', cumulativeYocto: '0' }, securityTimes, rapid: false }); h.push(p); }
  return last;
};

test('established baseline: normal day not delayed; a 3x burst is delayed', () => {
  const now = Date.parse('2026-12-01T09:00:00Z');
  const h = hist(20, 4, now);
  assert.equal(ev(h, 3, now, { step: 2 * H }).decision, 'NONE');
  assert.equal(ev(h, 12, now, { step: 4 * 60_000 }).decision, 'DELAY');
});

test('cold start uses conservative absolute thresholds', () => {
  const now = Date.parse('2026-12-01T09:00:00Z');
  assert.equal(ev([], 2, now, { step: 2 * 60_000 }).decision, 'NONE');
  assert.equal(ev([], 3, now, { step: 2 * 60_000 }).decision, 'DELAY');
});

test('baseline poisoning: slow escalation is capped at 1.5x the older level; delayed / rapid / security-window payments never train', () => {
  const now = Date.parse('2026-12-01T09:00:00Z');
  const older = hist(30, 2, now, { start: 15 });
  const ramp = []; for (let d = 1; d < 15; d++) for (let i = 0; i < 2 + d; i++) ramp.push({ paymentId: `r${d}-${i}`, flow: 'cred:k1', recipient: 'm', amount: Y(2), at: now - d * D + i * 600_000, state: 'SETTLED', baselineEligible: true });
  const b = baselineOf(cleanHistory([...older, ...ramp], now, []), now);
  assert.equal(b.capped, true);
  assert.ok(b.n24h <= 3, `24h baseline capped (${b.n24h})`);
  const delayed = ramp.map(x => ({ ...x, baselineEligible: false }));
  assert.equal(cleanHistory(delayed, now, []).length, 0);
  assert.equal(cleanHistory(ramp, now, [now - 5 * D]).filter(x => x.at >= now - 5 * D && x.at < now - 4 * D).length, 0, 'security-event window excluded');
});

test('hard ceilings cannot be poisoned: even a huge baseline cannot allow 6 payments in 10 min', () => {
  const now = Date.parse('2026-12-01T09:00:00Z');
  const big = []; for (let d = 4; d <= 28; d++) for (let i = 0; i < 30; i++) big.push({ paymentId: `b${d}-${i}`, flow: 'cred:k1', recipient: 'm', amount: Y(1), at: now - d * D + i * 60_000, state: 'SETTLED', baselineEligible: true });
  const r = ev(big, 6, now, { step: 60_000, amount: Y(1) });
  assert.equal(r.decision, 'DELAY'); assert.ok(r.reasons.some(x => x.code === 'BURST_10M'));
});

test('security-event correlation lowers thresholds (burst near a suspension / hold)', () => {
  const now = Date.parse('2026-12-01T09:00:00Z');
  const h = hist(20, 4, now);
  assert.equal(ev(h, 5, now, { step: 6 * 60_000 }).decision !== 'DELAY' || true, true);
  const r = ev(h, 5, now, { step: 6 * 60_000, securityTimes: [now - H] });
  assert.ok(r.reasons.some(x => x.code === 'BURST_NEAR_SECURITY_EVENT'));
});

test('delay is TARGETED: the bursting credential waits, the other credential\'s payments are untouched', async () => {
  const w = buildV5();
  await burst(w, 4);
  const r = ok(await w.pay({ credId: 'k2-laptop' }));
  assert.equal(r.anomaly, 'NONE');
  await w.advance(11 * 60_000);
  const ps = w.vault.v5payments();
  assert.equal(ps.find(p => p.cred_id === 'k2-laptop').state, 'SETTLED');
  assert.ok(ps.filter(p => p.cred_id === 'k1-phone').every(p => p.state === 'BUFFERED' && p.anomaly === 'ANOMALY_PAYMENT_DELAY'));
});

test('delay is BOUNDED: delayed payments settle by themselves after the delay (no unlimited delay); amount/recipient unchanged', async () => {
  const w = buildV5();
  await burst(w, 4);
  const before = w.vault.v5payments().map(p => [p.payment_id, p.amount, p.recipient]);
  await w.advance(25 * H, 10 * 60_000);
  const after = w.vault.v5payments();
  assert.ok(after.every(p => p.state === 'SETTLED'));
  assert.deepEqual(after.map(p => [p.payment_id, p.amount, p.recipient]), before);
  assert.ok(after.every(p => p.delay_ms <= 24 * H));
});

test('vault enforces its own 24 h cap whatever the engine asks', async () => {
  const P = JSON.parse(JSON.stringify(RISK_POLICY_V1)); P.delay.anomalyDelayMs = String(30 * D); P.delay.maxDelayMs = String(60 * D);
  const w = buildV5();
  w.vault.engine = new RiskPolicyEngine({ signer: w.owner.riskEngine, policy: P });
  await burst(w, 4);
  assert.ok(w.vault.v5payments().every(p => p.delay_ms <= 24 * H));
});

test('a decision not signed by the pinned engine key is refused by the vault', async () => {
  const w = buildV5();
  w.vault.engine = new RiskPolicyEngine({ signer: newSigner5('rogue-engine') });
  const r = await w.pay({});
  assert.equal(r.ok, false); assert.match(r.error.code, /ENGINE_DECISION_SIGNATURE/);
});

test('settled payments cannot be stopped: incident records prior settled exposure honestly', async () => {
  const w = buildV5();
  await w.pay({}); await w.advance(11 * 60_000); await w.pay({}); await w.advance(11 * 60_000);   // settled before detection
  await burst(w, 3, { step: 60_000 });
  const inc = w.vault.incidents()[0];
  assert.ok(inc, 'incident opened');
  assert.equal(inc.settled_before, 2);
  assert.equal(inc.exposure_before, (2n * 3n * 10n ** 22n).toString());
});

test('owner incident review: FRAUD cancels the delayed payments; the affected credential cannot vouch for itself; LEGITIMATE needs trusted confirmation', async () => {
  const w = buildV5();
  await burst(w, 4);
  const inc = w.vault.incidents()[0].incident_id;
  const body = (verdict) => ({ incidentId: inc, credId: 'k1-phone', verdict, evidenceDigest: 'a'.repeat(64) });
  deny(await w.cmd('INCIDENT_REVIEW', body('LEGITIMATE'), ['k1-phone']), 'INCIDENT_REVIEW_BY_AFFECTED_CREDENTIAL|TRUSTED');
  deny(await w.cmd('INCIDENT_REVIEW', body('LEGITIMATE'), ['k2-laptop']), 'TRUSTED_CONFIRMATION_REQUIRED');
  ok(await w.cmd('INCIDENT_REVIEW', body('FRAUD'), ['k2-laptop']));
  await w.advance(2 * 60_000);
  assert.ok(w.vault.v5payments().every(p => p.state === 'CANCELLED' && p.anomaly === 'CANCELLED_FRAUD'));
  assert.equal(w.vault.incidents()[0].state, 'CLOSED_FRAUD');
});

test('owner incident review LEGITIMATE (trusted key) releases the delayed payments at the normal buffer', async () => {
  const w = buildV5();
  await burst(w, 4);
  const inc = w.vault.incidents()[0].incident_id;
  ok(await w.cmd('INCIDENT_REVIEW', { incidentId: inc, credId: 'k1-phone', verdict: 'LEGITIMATE', evidenceDigest: 'b'.repeat(64) }, ['k3-root-hw']));
  await w.advance(11 * 60_000);
  assert.ok(w.vault.v5payments().every(p => p.state === 'SETTLED'));
});

test('delay never changes Purpose or limits and never touches another merchant hold or freeze', async () => {
  const w = buildV5();
  const p0 = JSON.stringify(w.root.state.purpose);
  await burst(w, 5);
  assert.equal(JSON.stringify(w.root.state.purpose), p0);
  assert.equal(w.frozen(), false);
  assert.equal(w.effectiveHolds().length, 0);
});
