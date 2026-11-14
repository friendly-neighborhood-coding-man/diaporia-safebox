// V5 behavioural anomaly detector: transparent, deterministic, reproducible. No model is involved.
// Features per payment FLOW (one payment credential or one delegated capability) over sliding windows, compared with
//   (a) predefined cold-start priors derived from the Purpose limits,
//   (b) an account/flow-specific baseline learned ONLY from reviewed, clean history (settled >= 72 h ago, never delayed,
//       never under Rapid-Use, never inside an incident, never within 24 h after a security event), and
//   (c) absolute hard ceilings that no baseline can raise (baseline-poisoning floor).
// The baseline may grow at most `baselineGrowthCap` x per 14 days (slow-escalation defence).
import { createHash } from 'node:crypto';
import { canon } from '../../v3/common/canon.mjs';

const MIN = 60_000, HOUR = 3600_000, DAY = 86_400_000;
export const RISK_POLICY_V1 = Object.freeze({
  version: 'risk-policy-v1',
  windows: { short: String(10 * MIN), hour: String(HOUR), day: String(DAY) },
  hard: { count10m: '6', count1h: '15', count24h: '40', value1hOfRemainingDaily: '0.40', value24hOfRemainingCumulative: '0.20', perHourCeilingDuringRapid: '90' },
  coldStart: { minPayments: '20', minSpanMs: String(7 * DAY), count10m: '3', count1h: '5', count24h: '14', value1hOfDailyLimit: '0.15', value24hOfDailyLimit: '0.35' },
  baseline: { countFactor: '2', countSlack: '2', valueFactor: '2', minHistoryAgeMs: String(72 * HOUR), lookbackMs: String(30 * DAY), growthWindowMs: String(14 * DAY), baselineGrowthCap: '1.5', securityQuietMs: String(DAY) },
  soft: { sameMerchant1h: '4', largeFirstPaymentOfPerPaymentMax: '0.9', securityCorrelationFactor: '0.5', newActiveHourMinHistory: '30' },
  decision: { delayScore: '2', watchScore: '1' },
  delay: { anomalyDelayMs: String(6 * HOUR), maxDelayMs: String(24 * HOUR), escalateAfterDelayed: '3', incidentQuietCloseMs: String(24 * HOUR) },
});
export const policyDigest = (p = RISK_POLICY_V1) => createHash('sha256').update('safebox.v5.risk-policy\u0000' + canon(JSON.parse(JSON.stringify(p)))).digest('hex');

const big = (x) => BigInt(x);
const frac = (num, den) => den <= 0n ? (num > 0n ? 1 : 0) : Number(num * 10000n / den) / 10000;
function pct(sorted, p) { if (!sorted.length) return 0; const i = Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1); return sorted[Math.max(0, i)]; }

/** Clean history usable for the baseline (never fabricated, never model output). */
export function cleanHistory(hist, now, securityTimes, P = RISK_POLICY_V1) {
  const minAge = Number(P.baseline.minHistoryAgeMs), look = Number(P.baseline.lookbackMs), quiet = Number(P.baseline.securityQuietMs);
  return hist.filter(p => p.state === 'SETTLED' && p.baselineEligible && p.at <= now - minAge && p.at >= now - look && !securityTimes.some(t => p.at >= t && p.at < t + quiet));
}
function hourly(list) { const m = new Map(); for (const p of list) { const k = Math.floor(p.at / HOUR); const e = m.get(k) ?? { n: 0, v: 0n }; e.n++; e.v += big(p.amount); m.set(k, e); } return [...m.values()]; }
function daily(list) { const m = new Map(); for (const p of list) { const k = Math.floor(p.at / DAY); const e = m.get(k) ?? { n: 0, v: 0n }; e.n++; e.v += big(p.amount); m.set(k, e); } return [...m.values()]; }

/** Baseline levels (p95 of active hours / days) with the growth cap applied against the older half of the lookback. */
export function baselineOf(clean, now, P = RISK_POLICY_V1) {
  const span = clean.length ? Math.max(...clean.map(p => p.at)) - Math.min(...clean.map(p => p.at)) : 0;
  const cold = clean.length < Number(P.coldStart.minPayments) || span < Number(P.coldStart.minSpanMs);
  const lvl = (list) => {
    const h = hourly(list), d = daily(list);
    return { n1h: pct(h.map(x => x.n).sort((a, b) => a - b), 0.95), v1h: h.length ? [...h.map(x => x.v)].sort((a, b) => (a < b ? -1 : 1))[Math.max(0, Math.ceil(0.95 * h.length) - 1)] : 0n,
      n24h: pct(d.map(x => x.n).sort((a, b) => a - b), 0.95), v24h: d.length ? [...d.map(x => x.v)].sort((a, b) => (a < b ? -1 : 1))[Math.max(0, Math.ceil(0.95 * d.length) - 1)] : 0n };
  };
  const all = lvl(clean);
  const older = clean.filter(p => p.at < now - Number(P.baseline.growthWindowMs));
  let capped = false;
  if (older.length >= 10) {
    // slow-escalation defence: the accepted level cannot exceed growthCap x the older level
    const o = lvl(older), g = Number(P.baseline.baselineGrowthCap);
    const capN = (a, b) => { const c = Math.max(1, Math.floor(b * g)); if (a > c) { capped = true; return c; } return a; };
    const capV = (a, b) => { const c = b * BigInt(Math.round(g * 100)) / 100n; if (a > c && c > 0n) { capped = true; return c; } return a; };
    all.n1h = capN(all.n1h, o.n1h); all.n24h = capN(all.n24h, o.n24h); all.v1h = capV(all.v1h, o.v1h); all.v24h = capV(all.v24h, o.v24h);
  }
  const hours = new Set(clean.map(p => new Date(p.at).getUTCHours()));
  return { cold, size: clean.length, ...all, activeHours: hours, capped };
}

/**
 * Evaluate a candidate payment `p` of `flow` at `now`.
 * ctx = { history (all payments of the account, trusted vault data), purpose, spent: {last24hYocto, cumulativeYocto}, securityTimes, rapid: bool }
 */
export function evaluate(p, ctx, P = RISK_POLICY_V1) {
  const now = p.at; const flowHist = ctx.history.filter(x => x.flow === p.flow && x.paymentId !== p.paymentId && ['RESERVED', 'BUFFERED', 'RELEASED', 'UNKNOWN', 'SETTLED', 'FROZEN'].includes(x.state));
  const win = (ms) => [...flowHist.filter(x => x.at > now - ms), p];
  const w10 = win(Number(P.windows.short)), w1h = win(Number(P.windows.hour)), w24 = win(Number(P.windows.day));
  const sum = (l) => l.reduce((t, x) => t + big(x.amount), 0n);
  const v1h = sum(w1h), v24 = sum(w24);
  const sec = ctx.securityTimes.some(t => t > now - DAY && t <= now);
  const k = sec ? Number(P.soft.securityCorrelationFactor) : 1;
  const purpose = ctx.purpose; const dailyLimit = big(purpose.dailyLimitYocto), cumLimit = big(purpose.cumulativeLimitYocto);
  // remaining budget at the START of the window (ctx.spent excludes p; the flow's own window spend is added back)
  const clamp = (x) => x > 0n ? x : 1n;
  const remainingDaily = clamp(dailyLimit - (big(ctx.spent.last24hYocto) - (v1h - big(p.amount))));
  const remainingCum = clamp(cumLimit - (big(ctx.spent.cumulativeYocto) - (v24 - big(p.amount))));
  const clean = cleanHistory(ctx.history.filter(x => x.flow === p.flow), now, ctx.securityTimes, P);
  const base = baselineOf(clean, now, P);
  const reasons = []; let score = 0; let hard = false;
  const H = (code, detail) => { reasons.push({ code, cls: 'HARD', detail }); hard = true; };
  const S = (code, w, detail) => { reasons.push({ code, cls: 'SOFT', weight: String(w), detail }); score += w; };
  // hard ceilings (independent of any baseline: cannot be poisoned)
  if (w10.length >= Number(P.hard.count10m)) H('BURST_10M', `${w10.length} payments in 10 min`);
  if (w1h.length >= Number(P.hard.count1h)) H('BURST_1H', `${w1h.length} payments in 1 h`);
  if (w24.length >= Number(P.hard.count24h)) H('BURST_24H', `${w24.length} payments in 24 h`);
  if (frac(v1h, remainingDaily) >= Number(P.hard.value1hOfRemainingDaily)) H('RAPID_DAILY_BUDGET_USE', `${(frac(v1h, remainingDaily) * 100).toFixed(1)}% of remaining daily budget in 1 h`);
  if (frac(v24, remainingCum) >= Number(P.hard.value24hOfRemainingCumulative)) H('RAPID_CUMULATIVE_BUDGET_USE', `${(frac(v24, remainingCum) * 100).toFixed(1)}% of remaining cumulative budget in 24 h`);
  if (ctx.rapid && w1h.length >= Number(P.hard.perHourCeilingDuringRapid)) H('RAPID_USE_VELOCITY_CEILING', `${w1h.length}/h during Rapid-Use`);
  if (base.cold) {
    const C = P.coldStart;
    if (w10.length >= Math.max(2, Math.floor(Number(C.count10m) * k))) S('COLD_BURST_10M', 2, `${w10.length} in 10 min (cold start)`);
    else if (w1h.length >= Math.max(2, Math.floor(Number(C.count1h) * k))) S('COLD_BURST_1H', 2, `${w1h.length} in 1 h (cold start)`);
    if (w24.length >= Math.max(3, Math.floor(Number(C.count24h) * k))) S('COLD_VOLUME_24H', 1, `${w24.length} in 24 h (cold start)`);
    if (frac(v1h, dailyLimit) >= Number(C.value1hOfDailyLimit) * k) S('COLD_VALUE_1H', 1, `${(frac(v1h, dailyLimit) * 100).toFixed(1)}% of daily limit in 1 h`);
    if (frac(v24, dailyLimit) >= Number(C.value24hOfDailyLimit) * k) S('COLD_VALUE_24H', 1, `${(frac(v24, dailyLimit) * 100).toFixed(1)}% of daily limit in 24 h`);
  } else {
    const B = P.baseline;
    const lim1h = Math.max(3, Math.floor((base.n1h * Number(B.countFactor) + Number(B.countSlack)) * k));
    const lim24 = Math.max(4, Math.floor((base.n24h * Number(B.countFactor) + Number(B.countSlack)) * k));
    if (w1h.length > lim1h) S('RATE_ABOVE_BASELINE_1H', 2, `${w1h.length} vs baseline p95 ${base.n1h}/h`);
    if (w24.length > lim24) S('RATE_ABOVE_BASELINE_24H', 1, `${w24.length} vs baseline p95 ${base.n24h}/day`);
    const vlim1 = base.v1h * BigInt(Number(B.valueFactor)), vlim24 = base.v24h * BigInt(Number(B.valueFactor));
    if (v1h > (vlim1 > dailyLimit / 20n ? vlim1 : dailyLimit / 20n)) S('VALUE_ABOVE_BASELINE_1H', 1, `value 1 h above ${B.valueFactor}x baseline`);
    if (v24 > (vlim24 > dailyLimit / 10n ? vlim24 : dailyLimit / 10n)) S('VALUE_ABOVE_BASELINE_24H', 1, `value 24 h above ${B.valueFactor}x baseline`);
    if (clean.length >= Number(P.soft.newActiveHourMinHistory) && !base.activeHours.has(new Date(now).getUTCHours())) S('UNUSUAL_ACTIVE_HOUR', 0.5, `UTC hour ${new Date(now).getUTCHours()} never seen in clean history`);
  }
  const sameM = w1h.filter(x => x.recipient === p.recipient).length;
  if (sameM >= Number(P.soft.sameMerchant1h)) S('REPEATED_SAME_MERCHANT', 0.5, `${sameM} to ${p.recipient} in 1 h`);
  if (!clean.length && frac(big(p.amount), big(purpose.perPaymentMaxYocto)) >= Number(P.soft.largeFirstPaymentOfPerPaymentMax)) S('LARGE_FIRST_PAYMENT', 0.5, 'first-time large payment (alone never a delay)');
  if (sec && w1h.length >= 3) S('BURST_NEAR_SECURITY_EVENT', 1, 'payment burst within 24 h of a suspension / recovery / hold event');
  const decision = hard || score >= Number(P.decision.delayScore) ? 'DELAY' : score >= Number(P.decision.watchScore) ? 'WATCH' : 'NONE';
  return { decision, hard, score: String(score), reasons, features: { flow: p.flow, count10m: String(w10.length), count1h: String(w1h.length), count24h: String(w24.length), value1h: v1h.toString(), value24h: v24.toString(),
    remainingDaily: remainingDaily.toString(), coldStart: String(base.cold), baselineSize: String(base.size), baselineN1h: String(base.n1h), baselineCapped: String(base.capped), securityCorrelated: String(sec) }, policy: P.version };
}
