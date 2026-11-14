// Runs the V5.1 matched A/B experiments and writes docs/evidence/v51/ab-results.json + ab-summary.md.
// Primary comparison: A (FIXED_600) vs B (EXP_30). Exploratory arms (X_*) are reported separately and never decide.
// Acceptance criteria are fixed in docs/v51/AB-PROTOCOL.md before this script's full run.
import { writeFileSync, mkdirSync } from 'node:fs';
import { runAll } from '../../src/v5/sim/v51-experiments.mjs';

const seeds = (process.env.SEEDS ?? '11,23,37,41,53').split(',').map(Number);
const arms = (process.env.ARMS ?? 'A,B,X_HV').split(',');
const t0 = Date.now();
const raw = await runAll({ seeds, arms, log: (l) => process.stderr.write(l + '\n') });
const sec = (ms) => ms === null ? null : ms / 1000;
const pctl = (xs, p) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))]; };
const ATTACK = (n) => /^0[1-5]|^02b|^08|^09|^11|^13|^14/.test(n);
const agg = {};
for (const [name, byArm] of Object.entries(raw.results)) {
  agg[name] = {};
  for (const [arm, runs] of Object.entries(byArm)) {
    const lat = runs.flatMap(r => r.legit.latencyMs);
    const sum = (f) => runs.reduce((t, r) => t + f(r), 0);
    agg[name][arm] = {
      runs: runs.length,
      attackerSettledNEAR_total: +sum(r => r.attacker.settledNEAR).toFixed(3), attackerSettledNEAR_max: Math.max(...runs.map(r => r.attacker.settledNEAR)),
      attackerSettledBeforeDetectionNEAR_total: +sum(r => r.attacker.settledBeforeDetectionNEAR).toFixed(3),
      attackerPaymentsSettled: sum(r => r.attacker.settled),
      legitSettled: sum(r => r.legit.settled), legitAttempted: sum(r => r.legit.attemptedIncludingDenied),
      legitLatencyS: { p50: sec(pctl(lat, 0.5)), p95: sec(pctl(lat, 0.95)), p99: sec(pctl(lat, 0.99)), n: lat.length },
      falsePositiveDelays: sum(r => r.legit.falsePositiveDelays), falsePositiveCancellations: sum(r => r.legit.falsePositiveCancellations),
      legitDeniedAtProposal: sum(r => Object.values(r.legit.deniedAtProposal).reduce((a, b) => a + b, 0)), pendingSlotExhaustion: sum(r => r.legit.pendingSlotExhaustion),
      ownerPrompts: sum(r => r.owner.prompts), firstDetectAtS: runs.map(r => r.detection.firstDetectAtMs === null ? null : r.detection.firstDetectAtMs / 1000),
      verifierOk: runs.every(r => r.verifier.ok), horizonViolations: sum(r => r.verifier.horizonViolations ?? 0), unauthorizedAuthority: sum(r => r.verifier.unauthorizedAuthority),
      violations: [...new Set(runs.flatMap(r => r.verifier.violations))],
      decisionMsP99: Math.max(...runs.map(r => r.overhead.decisionMsP99 ?? 0)), journalBytesMean: Math.round(sum(r => r.overhead.journalBytes) / runs.length), v5payBytesMean: Math.round(sum(r => r.overhead.v5payBytes) / runs.length),
      perSeedAttackerNEAR: runs.map(r => r.attacker.settledNEAR),
    };
  }
}
// overall legitimate experience (all scenarios pooled)
const overall = {};
for (const arm of arms) {
  const runs = Object.values(raw.results).flatMap(x => x[arm] ?? []);
  const lat = runs.flatMap(r => r.legit.latencyMs);
  const settled = runs.reduce((t, r) => t + r.legit.settled, 0), attempted = runs.reduce((t, r) => t + r.legit.attemptedIncludingDenied, 0);
  overall[arm] = { legitSuccessRate: attempted ? +(settled / attempted).toFixed(4) : null, legitSettled: settled, legitAttempted: attempted,
    legitLatencyS: { p50: sec(pctl(lat, 0.5)), p95: sec(pctl(lat, 0.95)), p99: sec(pctl(lat, 0.99)), n: lat.length },
    attackerSettledNEAR_total: +Object.entries(raw.results).filter(([n]) => ATTACK(n)).flatMap(([, x]) => x[arm] ?? []).reduce((t, r) => t + r.attacker.settledNEAR, 0).toFixed(3),
    attackerSettledBeforeDetectionNEAR_total: +Object.entries(raw.results).filter(([n]) => ATTACK(n)).flatMap(([, x]) => x[arm] ?? []).reduce((t, r) => t + r.attacker.settledBeforeDetectionNEAR, 0).toFixed(3),
    falsePositiveDelays: runs.reduce((t, r) => t + r.legit.falsePositiveDelays, 0), falsePositiveCancellations: runs.reduce((t, r) => t + r.legit.falsePositiveCancellations, 0),
    verifierOkAll: runs.every(r => r.verifier.ok), horizonViolations: runs.reduce((t, r) => t + (r.verifier.horizonViolations ?? 0), 0), unauthorizedAuthority: runs.reduce((t, r) => t + r.verifier.unauthorizedAuthority, 0),
    ownerPrompts: runs.reduce((t, r) => t + r.owner.prompts, 0) };
}
// prespecified acceptance (docs/v51/AB-PROTOCOL.md) for a candidate arm vs A, matched run by matched run
function accept(c) {
  const increases = [];
  for (const [n, x] of Object.entries(raw.results)) { if (!x[c] || !x.A) continue; x[c].forEach((r, i) => { const a = x.A[i]; if (r.attacker.settledNEAR > a.attacker.settledNEAR + 1e-9) increases.push({ scenario: n, seed: r.seed, A: a.attacker.settledNEAR, [c]: r.attacker.settledNEAR }); }); }
  const S1 = overall[c].verifierOkAll && overall[c].horizonViolations === 0 && overall[c].unauthorizedAuthority === 0;
  const S2 = increases.length === 0;
  const L1 = overall[c].legitSuccessRate >= overall.A.legitSuccessRate;
  const L2 = overall[c].legitLatencyS.p95 !== null && overall.A.legitLatencyS.p95 !== null && overall[c].legitLatencyS.p95 < overall.A.legitLatencyS.p95; // null p95 never passes
  return { S1_invariants: S1, S2_noAttackerIncrease: S2, L1_successNotWorse: L1, L2_p95Improved: L2, accepted: S1 && S2 && L1 && L2, attackerIncreases: increases };
}
const decision = Object.fromEntries(arms.filter(a => a !== 'A').map(a => [a, accept(a)]));
const out = { generatedBy: 'scripts/v5/run-v51-ab.mjs', commit: process.env.GIT_COMMIT ?? null, seeds, arms, wallMs: Date.now() - t0, overall, decision, aggregate: agg, raw };
mkdirSync('docs/evidence/v51', { recursive: true });
writeFileSync('docs/evidence/v51/ab-results.json', JSON.stringify(out, null, 1) + '\n');
// markdown summary
const L = [];
L.push(`# V5.1 A/B results (generated)`, '', `Seeds ${seeds.join(', ')}; arms ${arms.join(', ')}; commit ${out.commit ?? '-'}. A = FIXED_600 (control), B = EXP_30 (prespecified candidate), X_HV = exploratory.`, '');
L.push('| scenario | arm | attacker settled NEAR (sum over seeds) | before detection | legit settled/attempted | legit p50/p95/p99 s | FP delays | FP cancels | legit refused | verifier |', '|---|---|---|---|---|---|---|---|---|---|');
for (const [n, x] of Object.entries(agg)) for (const [arm, m] of Object.entries(x))
  L.push(`| ${n} | ${arm} | ${m.attackerSettledNEAR_total} | ${m.attackerSettledBeforeDetectionNEAR_total} | ${m.legitSettled}/${m.legitAttempted} | ${m.legitLatencyS.p50 ?? '-'}/${m.legitLatencyS.p95 ?? '-'}/${m.legitLatencyS.p99 ?? '-'} | ${m.falsePositiveDelays} | ${m.falsePositiveCancellations} | ${m.legitDeniedAtProposal} | ${m.verifierOk ? 'ok' : 'FAIL ' + m.violations.join(',')} |`);
L.push('', '## Overall', '', '```json', JSON.stringify(overall, null, 1), '```', '', '## Prespecified acceptance', '', '```json', JSON.stringify(decision, null, 1), '```');
writeFileSync('docs/evidence/v51/ab-summary.md', L.join('\n') + '\n');
console.log(JSON.stringify({ overall, decision: Object.fromEntries(Object.entries(decision).map(([k, v]) => [k, { ...v, attackerIncreases: v.attackerIncreases.length }])) }, null, 1));
