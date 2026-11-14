// SafeBox V5.1 (P4) settlement-buffer policies. EXPERIMENTAL: the tiers are a prespecified candidate, not proven optimal.
//   FIXED_600 : every payment waits 600 s (V5 baseline, Control A).
//   EXP_30    : bufferSeconds(n) = min(600, 30 * 2^n), n = deterministic bounded risk tier (Candidate B).
// The tier is a pure function of signed, integer-valued inputs (tierFromInputs) so that the vault and the independent
// verifier can both recompute it. The buffer is the MINIMUM wait before release; the anomaly delay (P1) is separate and
// added on top; Rapid-Use can remove only the anomaly delay, never this buffer.
const BPS = 10_000n;
export const MAX_BUFFER_MS = 600_000;
export const MAX_TIER = 5;
// EXP_30_HV is an EXPLORATORY variant (not the prespecified candidate): EXP_30, except that a flow whose value over the
// last hour reaches half the per-payment maximum always gets tier 5 (600 s). Only low-value activity is accelerated.
export const EXP_POLICIES = new Set(['EXP_30', 'EXP_30_HV']);
export const bufferFloorMs = (policy) => EXP_POLICIES.has(policy) ? 30_000 : 600_000;
export function tierToBufferMs(policy, tier) {
  if (!EXP_POLICIES.has(policy)) return MAX_BUFFER_MS;
  const n = Number(tier);
  if (!Number.isInteger(n) || n < 0) return MAX_BUFFER_MS; // malformed tier: fail safe
  return Math.min(MAX_BUFFER_MS, 30_000 * 2 ** Math.min(n, 10));
}
const bps = (num, den) => den <= 0n ? Number(BPS) : Number(num * BPS / den);

/**
 * Deterministic tier from the signed inputs. Every step is a fixed threshold; the result is clamped to [stickyTier, 5]:
 *  - value of the flow over the last hour (this payment included) relative to the per-payment maximum, so splitting one
 *    large payment into small ones lands on the same tier as the large payment;
 *  - daily and cumulative budget consumption (account level, this payment included);
 *  - recent frequency of the flow (10 min / 1 h);
 *  - deviation from verified clean history (cold start, or a baseline-relative detector reason);
 *  - correlated security events (24 h) and an open incident on the flow;
 *  - the detector's own level (WATCH / DELAY);
 *  - stickiness: never below the highest tier this flow received in the last hour (no reset by waiting a few minutes
 *    or by splitting).
 */
export function tierFromInputs(i, policy = 'EXP_30') {
  if (!i || typeof i !== 'object') return MAX_TIER;
  const N = (k) => Number(i[k]);
  if (policy === 'EXP_30_HV' && !(N('flowValue1hBps') < 5_000)) return MAX_TIER;
  let n = 0;
  const a = N('flowValue1hBps'); n += a >= 30_000 ? 3 : a >= 10_000 ? 2 : a >= 5_000 ? 1 : 0;
  const d = N('dailyUseBps'); n += d >= 5_000 ? 2 : d >= 2_500 ? 1 : 0;
  if (N('cumulativeUseBps') >= 5_000) n += 1;
  if (N('count10m') >= 2) n += 1;
  if (N('count1h') >= 4) n += 1;
  if (i.coldStart === 'true') n += 1;
  if (i.baselineDeviation === 'true') n += 1;
  if (i.securityCorrelated === 'true') n += 2;
  if (i.openIncident === 'true') n += 3;
  n += i.detectorLevel === 'DELAY' ? 2 : i.detectorLevel === 'WATCH' ? 1 : 0;
  n = Math.max(n, N('stickyTier') || 0);
  if (!Number.isFinite(n)) return MAX_TIER;
  return Math.min(MAX_TIER, n);
}

const BASELINE_REASONS = new Set(['RATE_ABOVE_BASELINE_1H', 'RATE_ABOVE_BASELINE_24H', 'VALUE_ABOVE_BASELINE_1H', 'VALUE_ABOVE_BASELINE_24H', 'UNUSUAL_ACTIVE_HOUR']);
/** Build the signed inputs from the detector evaluation and trusted vault context, then decide. */
export function bufferDecision(p, ctx, ev, { policy = 'FIXED_600', openIncident = null } = {}) {
  const per = BigInt(ctx.purpose.perPaymentMaxYocto), day = BigInt(ctx.purpose.dailyLimitYocto), cum = BigInt(ctx.purpose.cumulativeLimitYocto), amt = BigInt(p.amount);
  const v1h = BigInt(ev.features.value1h);
  const sticky = ctx.history.filter(x => x.flow === p.flow && x.paymentId !== p.paymentId && x.at > p.at - 3600_000 && x.at <= p.at && x.tier !== null && x.tier !== undefined)
    .reduce((m, x) => Math.max(m, Number(x.tier)), 0);
  const inputs = {
    flowValue1hBps: String(bps(v1h > amt ? v1h : amt, per)),
    dailyUseBps: String(bps(BigInt(ctx.spent.last24hYocto) + amt, day)),
    cumulativeUseBps: String(bps(BigInt(ctx.spent.cumulativeYocto) + amt, cum)),
    count10m: ev.features.count10m, count1h: ev.features.count1h,
    coldStart: ev.features.coldStart, baselineDeviation: String(ev.reasons.some(r => BASELINE_REASONS.has(r.code))),
    securityCorrelated: ev.features.securityCorrelated, openIncident: String(!!openIncident),
    detectorLevel: ev.decision, stickyTier: String(sticky),
  };
  if (!EXP_POLICIES.has(policy)) return { policy: 'FIXED_600', tier: '-', bufferMs: String(MAX_BUFFER_MS), inputs };
  const tier = tierFromInputs(inputs, policy);
  return { policy, tier: String(tier), bufferMs: String(tierToBufferMs(policy, tier)), inputs };
}
