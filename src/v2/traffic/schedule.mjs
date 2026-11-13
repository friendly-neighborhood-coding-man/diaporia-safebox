// Deterministic seeded workload generator (Supervisor/controller side ONLY: it knows the labels).
// - inter-arrival uniform in [90 s, 150 s] (mean 120 s)
// - per simulated hour an attack probability drawn from HOURLY_ATTACK_PROBABILITY
// - per request an independent attack/normal label
// - normal AND attack requests draw the amount from the SAME AMOUNT_DISTRIBUTION, using the same
//   RNG draw position, so the amount carries no information about the label.
import { makeRng } from '../common/rng.mjs';
import { AMOUNT_DISTRIBUTION, HOURLY_ATTACK_PROBABILITY } from '../common/amounts.mjs';

export function generateWorkload({ seed, hours = 24, t0, techniques, merchants, minGapMs = 90_000, maxGapMs = 150_000 }) {
  const rng = makeRng('workload:' + seed);
  const labelRng = makeRng('labels:' + seed), techRng = makeRng('tech:' + seed), amountRng = makeRng('amount:' + seed), merchRng = makeRng('merchant:' + seed);
  const hourly = [];
  for (let h = 0; h < hours; h++) hourly.push(labelRng.weighted(HOURLY_ATTACK_PROBABILITY));
  const events = [];
  let t = t0, i = 0;
  const end = t0 + hours * 3600_000;
  for (;;) {
    t += rng.int(minGapMs, maxGapMs);
    if (t >= end) break;
    const hour = Math.floor((t - t0) / 3600_000);
    const pct = hourly[hour];
    const attack = labelRng.int(0, 99) < pct;
    events.push({ i: i++, t, hour, hourAttackPct: pct, label: attack ? 'attack' : 'normal',
      technique: attack ? techRng.pick(techniques) : null,
      amountYocto: amountRng.weighted(AMOUNT_DISTRIBUTION), merchant: merchRng.pick(merchants) });
  }
  return { seed, hours, hourly, events };
}

export function summarize(workload) {
  const n = workload.events.length, attacks = workload.events.filter(e => e.label === 'attack').length;
  const amounts = {};
  for (const e of workload.events) { amounts[e.label] ??= {}; amounts[e.label][e.amountYocto] = (amounts[e.label][e.amountYocto] ?? 0) + 1; }
  const gaps = workload.events.slice(1).map((e, k) => e.t - workload.events[k].t);
  return { requests: n, attacks, attackRate: n ? attacks / n : 0, meanGapMs: gaps.reduce((s, g) => s + g, 0) / Math.max(1, gaps.length),
    hourlyAttackPct: workload.hourly, amountHistogram: amounts };
}

/** SEEN regression suite: every technique `repeat` times, each followed by a normal request, 120 s apart.
 *  Amounts still come from AMOUNT_DISTRIBUTION for both labels. */
export function generateSuiteWorkload({ seed, t0, techniques, merchants, repeat = 1 }) {
  const amountRng = makeRng('suite-amount:' + seed), merchRng = makeRng('suite-merchant:' + seed);
  const events = []; let t = t0, i = 0;
  for (let k = 0; k < repeat; k++) for (const tech of techniques) for (const label of ['attack', 'normal']) {
    t += 120_000;
    events.push({ i: i++, t, hour: Math.floor((t - t0) / 3600_000), hourAttackPct: null, label, technique: label === 'attack' ? tech : null,
      amountYocto: amountRng.weighted(AMOUNT_DISTRIBUTION), merchant: merchRng.pick(merchants) });
  }
  return { seed, hours: Math.ceil((t - t0) / 3600_000), hourly: [], events, suite: true };
}
