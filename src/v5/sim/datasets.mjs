// Behavioural anomaly datasets: labelled benign and malicious payment trajectories, generated deterministically from a
// seed with a SHA-256 counter stream (standard hash; no custom random generator). Each trajectory = up to 21 days of
// reviewed history (seeded as trusted, settled history) + a 24 h evaluation window replayed through the real V5 vault.
import { createHash } from 'node:crypto';
import { buildV5, near } from '../world.mjs';

const MIN = 60_000, H = 3600_000, D = 86_400_000;
function stream(seed) { let i = 0; return () => { const h = createHash('sha256').update(`${seed}:${i++}`).digest(); return h.readUInt32BE(0) / 2 ** 32; }; }
const M = ['merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'];
const amt = (r, lo, hi) => near(Math.round((lo + r() * (hi - lo)) * 1000) / 1000);

/** history(t0) -> rows; window(t0) -> [{ dt, recipient, amount }] relative to the window start. */
export const PERSONAS = {
  // ---------- benign
  regular_shopper: { label: 'BENIGN', history: (r) => days(r, 21, () => 2 + Math.floor(r() * 4), { start: 9, span: 10, lo: 0.005, hi: 0.04 }), window: (r) => spread(r, 4, { start: 9 * H, span: 10 * H, lo: 0.005, hi: 0.04 }) },
  weekly_bulk_buyer: { label: 'BENIGN', history: (r) => [...days(r, 21, () => 1, { start: 10, span: 6, lo: 0.01, hi: 0.03 }), ...bulkDays(r, [7, 14, 21], 6)], window: (r) => burstAt(r, 10 * H, 6, 4 * MIN, 0.01, 0.03) },
  new_account_first_day: { label: 'BENIGN', history: () => [], window: (r) => spread(r, 3, { start: 8 * H, span: 12 * H, lo: 0.01, hi: 0.05 }) },
  new_account_large_first: { label: 'BENIGN', history: () => [], window: () => [{ dt: 9 * H, recipient: M[0], amount: near(0.058) }] },
  busy_merchant_rotation: { label: 'BENIGN', history: (r) => days(r, 21, () => 6 + Math.floor(r() * 4), { start: 8, span: 12, lo: 0.005, hi: 0.03 }), window: (r) => spread(r, 8, { start: 8 * H, span: 12 * H, lo: 0.005, hi: 0.03 }) },
  night_owl_shift_change: { label: 'BENIGN', history: (r) => days(r, 21, () => 3, { start: 9, span: 8, lo: 0.01, hi: 0.03 }), window: (r) => spread(r, 3, { start: 1 * H, span: 3 * H, lo: 0.01, hi: 0.03 }) },
  // ---------- malicious (stolen DAILY key, in-Purpose recipients and amounts)
  fast_burst: { label: 'MALICIOUS', history: (r) => days(r, 21, () => 3, { start: 9, span: 10, lo: 0.01, hi: 0.03 }), window: () => fixed(20, 3 * H, 20_000, 0.05) },
  medium_burst: { label: 'MALICIOUS', history: (r) => days(r, 21, () => 3, { start: 9, span: 10, lo: 0.01, hi: 0.03 }), window: () => fixed(15, 3 * H, 3 * MIN, 0.05) },
  slow_drain_max_amount: { label: 'MALICIOUS', history: (r) => days(r, 21, () => 3, { start: 9, span: 10, lo: 0.01, hi: 0.03 }), window: () => fixed(30, 1 * H, 30 * MIN, 0.058) },
  split_small: { label: 'MALICIOUS', history: (r) => days(r, 21, () => 3, { start: 9, span: 10, lo: 0.01, hi: 0.03 }), window: () => fixed(30, 2 * H, MIN, 0.004) },
  merchant_rotation_burst: { label: 'MALICIOUS', history: (r) => days(r, 21, () => 3, { start: 9, span: 10, lo: 0.01, hi: 0.03 }), window: () => fixed(18, 4 * H, 2 * MIN, 0.05).map((p, i) => ({ ...p, recipient: M[i % 3] })) },
  cold_start_theft: { label: 'MALICIOUS', history: () => [], window: () => fixed(12, 2 * H, 2 * MIN, 0.05) },
  poisoned_baseline: { label: 'MALICIOUS', history: (r) => [...days(r, 30, () => 2, { start: 9, span: 10, lo: 0.01, hi: 0.03, from: 15 }), ...ramp(r)], window: () => fixed(16, 2 * H, 4 * MIN, 0.05) },
  just_under_hourly: { label: 'MALICIOUS', history: (r) => days(r, 21, () => 3, { start: 9, span: 10, lo: 0.01, hi: 0.03 }), window: () => fixed(24, 0, 59 * MIN, 0.05) },
};
function days(r, n, perDay, { start, span, lo, hi, from = 1 }) {
  const out = []; for (let d = from; d <= n; d++) { const k = perDay(); for (let i = 0; i < k; i++) out.push({ dAgo: d, at: (start + r() * span) * H, recipient: M[Math.floor(r() * 3)], amount: amt(r, lo, hi) }); } return out;
}
function bulkDays(r, list, n) { const out = []; for (const d of list) for (let i = 0; i < n; i++) out.push({ dAgo: d, at: 10 * H + i * 4 * MIN, recipient: M[i % 3], amount: amt(r, 0.01, 0.03) }); return out; }
function ramp(r) { const out = []; for (let d = 14; d >= 4; d--) for (let k = 0; k < 2 + (15 - d); k++) out.push({ dAgo: d, at: 9 * H + k * 25 * MIN, recipient: M[0], amount: amt(r, 0.03, 0.05) }); return out; }
function spread(r, n, { start, span, lo, hi }) { return Array.from({ length: n }, () => ({ dt: start + Math.floor(r() * span / MIN) * MIN, recipient: M[Math.floor(r() * 3)], amount: amt(r, lo, hi) })).sort((a, b) => a.dt - b.dt); }
function burstAt(r, at, n, every, lo, hi) { return Array.from({ length: n }, (_, i) => ({ dt: at + i * every, recipient: M[i % 3], amount: amt(r, lo, hi) })); }
function fixed(n, at, every, a) { return Array.from({ length: n }, (_, i) => ({ dt: at + i * every, recipient: M[0], amount: near(a) })); }

/** Replays one trajectory through a fresh V5 world; returns detection / exposure / FP metrics. */
export async function runTrajectory(name, { seed = 1 } = {}) {
  const P = PERSONAS[name]; const r = stream(`${name}:${seed}`);
  const w = buildV5();
  const start = w.now() + 60_000;
  const hist = P.history(r).map(h => ({ credId: 'k1-phone', recipient: h.recipient, amount: h.amount, at: start - h.dAgo * D + h.at - 24 * H }));
  if (hist.length) w.vault.seedHistory(hist);
  const plan = P.window(r);
  let firstDetect = null, idx = 0; const res = [];
  for (const p of plan) {
    const target = start + p.dt;
    if (target > w.now()) await w.advance(target - w.now(), Math.min(10 * MIN, Math.max(MIN, target - w.now())));
    const q = await w.pay({ credId: 'k1-phone', recipientId: p.recipient, amountYocto: p.amount });
    res.push(q.ok ? q.result.anomaly : q.error.code);
    if (q.ok && q.result.anomaly !== 'NONE' && firstDetect === null) firstDetect = { index: idx, atMs: w.now() - start - plan[0].dt };
    idx++;
  }
  await w.advance(26 * H, 10 * MIN);
  const ps = w.vault.v5payments().filter(p => !/seeded/.test(p.decision ?? ''));
  const delayed = ps.filter(p => p.delay_ms > 0);
  const inc = w.vault.incidents()[0];
  const sum = (l) => l.reduce((t, x) => t + BigInt(x.amount), 0n).toString();
  return { name, label: P.label, historyPayments: hist.length, windowPayments: plan.length, accepted: ps.length, denied: res.filter(x => !['NONE', 'ANOMALY_PAYMENT_DELAY'].includes(x)).length,
    detected: delayed.length > 0, firstDetection: firstDetect, delayed: delayed.length, settledBeforeDetection: inc ? inc.settled_before : ps.filter(p => p.state === 'SETTLED').length,
    exposureBeforeDetectionYocto: inc ? inc.exposure_before : sum(ps.filter(p => p.state === 'SETTLED')), totalDelayMs: delayed.reduce((t, p) => t + Number(p.delay_ms), 0), maxDelayMs: Math.max(0, ...delayed.map(p => Number(p.delay_ms))),
    reasons: [...new Set(ps.flatMap(p => { try { return JSON.parse(p.decision).reasons ?? []; } catch { return []; } }))], emails: w.mock.sent.length };
}

export async function runDatasets({ seeds = [1, 2, 3] } = {}) {
  const rows = [];
  for (const name of Object.keys(PERSONAS)) for (const seed of seeds) rows.push({ seed, ...(await runTrajectory(name, { seed })) });
  const ben = rows.filter(r => r.label === 'BENIGN'), mal = rows.filter(r => r.label === 'MALICIOUS');
  const summary = {
    benignTrajectories: ben.length, falsePositives: ben.filter(r => r.detected).length, falsePositiveRate: ben.filter(r => r.detected).length / ben.length,
    falsePositiveDelayMsTotal: ben.reduce((t, r) => t + r.totalDelayMs, 0), falsePositiveMaxDelayMs: Math.max(0, ...ben.map(r => r.maxDelayMs)),
    maliciousTrajectories: mal.length, truePositives: mal.filter(r => r.detected).length, truePositiveRate: mal.filter(r => r.detected).length / mal.length, falseNegativeRate: mal.filter(r => !r.detected).length / mal.length,
    settledBeforeDetection: mal.reduce((t, r) => t + r.settledBeforeDetection, 0), exposureBeforeDetectionYocto: mal.reduce((t, r) => t + BigInt(r.exposureBeforeDetectionYocto), 0n).toString(),
    coldStart: { benign: ben.filter(r => r.historyPayments === 0).map(r => ({ name: r.name, detected: r.detected })), malicious: mal.filter(r => r.historyPayments === 0).map(r => ({ name: r.name, detected: r.detected, settledBefore: r.settledBeforeDetection })) },
  };
  return { summary, rows };
}
