#!/usr/bin/env node
// Final V2 evaluation on a FROZEN revision (src/, scripts/, tests/ must be clean). Writes docs/evidence/v2/final/<commit>/.
// Requires root on Linux for the OS-isolated runs (otherwise they are recorded as NOT VERIFIED).
// Usage: sudo node scripts/v2/evaluate.mjs [--holdout 500] [--hours 24]
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInProcess } from '../../src/v2/harness.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
process.chdir(ROOT);
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d; };
const head = execFileSync('git', ['rev-parse', 'HEAD']).toString().trim();
const dirty = execFileSync('git', ['status', '--porcelain', 'src', 'scripts', 'tests', 'package.json']).toString().trim();
if (dirty && !process.argv.includes('--allow-dirty')) { console.error('refusing: evaluated code must be committed (frozen)\n' + dirty); process.exit(2); }
const short = head.slice(0, 7), OUT = join(ROOT, 'docs/evidence/v2/final', short);
mkdirSync(OUT, { recursive: true });
const hours = Number(arg('hours', '24')), nHold = Number(arg('holdout', '500'));
const seed24 = 'eval24h:' + head.slice(0, 12);
const node = process.execPath, nw = '--disable-warning=ExperimentalWarning';
const log = (...a) => console.log(new Date().toISOString(), ...a);
const tapSummary = (t) => Object.fromEntries(['tests', 'pass', 'fail', 'skipped', 'cancelled'].map(k => [k, Number(new RegExp(`# ${k} (\\d+)`).exec(t)?.[1] ?? NaN)]));
const compactRows = (rows) => rows.map(r => ({ ...r, zone: r.zone ? { ...r.zone, steps: r.zone.steps?.map(s => [s.action, s.outcome, s.code, s.detail ?? null]), agentActions: r.zone.agentActions } : undefined }));
const isRoot = process.getuid?.() === 0;
const report = { kind: 'safebox-v2-final-evidence', gitHead: head, branch: execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD']).toString().trim(), node: process.version,
  startedAt: new Date().toISOString(), commands: {}, results: {} };

// 1. Regression: V1 + V2 (+ OS tests when root).
log('regression');
const reg = spawnSync(node, [nw, '--test'], { encoding: 'utf8', cwd: ROOT });
writeFileSync(join(OUT, 'regression.tap'), reg.stdout);
report.results.regression = { exit: reg.status, ...tapSummary(reg.stdout), v1: tapSummary(spawnSync(node, [nw, '--test', 'tests/mock.test.mjs', 'tests/v1/adversarial.test.mjs', 'tests/v1/contract-model-vectors.test.mjs', 'tests/v1/executor-verifier.test.mjs', 'tests/v1/intent-authz.test.mjs', 'tests/v1/store-concurrency.test.mjs'], { encoding: 'utf8' }).stdout) };
report.commands.regression = 'node --disable-warning=ExperimentalWarning --test';
const demo = spawnSync('npm', ['run', '-s', 'demo:v1'], { encoding: 'utf8', cwd: ROOT });
report.results.v1OfflineDemo = { exit: demo.status, tail: demo.stdout.split('\n').slice(-6).join('\n') };

// 2. Independent holdout (seed derived from the frozen commit).
log('holdout');
const hp = join(OUT, 'holdout.json');
const ho = spawnSync(node, [nw, 'scripts/v2/holdout.mjs', '--n', String(nHold), '--out', hp], { encoding: 'utf8' });
const H = JSON.parse(readFileSync(hp, 'utf8'));
report.results.holdout = { exit: ho.status, seed: H.seed, n: H.n, tally: H.tally, falsePositivesByMutation: H.falsePositivesByMutation, unauthorizedLedgerTransfers: H.unauthorizedLedgerTransfers,
  unattributedViolations: H.unattributedViolations, attackerBalance: H.attackerBalance, frozen: H.frozen, file: 'holdout.json' };
report.commands.holdout = `node scripts/v2/holdout.mjs --n ${nHold}   # seed = sha256(git HEAD)`;

// 3. In-process A/B/C on the identical seeded workload.
for (const mode of ['A', 'B', 'C']) {
  log('in-process', mode);
  const r = await runInProcess({ seed: seed24, hours, mode });
  const f = `inprocess-${mode}-${hours}h.json`;
  writeFileSync(join(OUT, f), JSON.stringify({ mode, seed: seed24, hours, boundary: 'in-process logical (OS isolation NOT exercised)', workloadSummary: r.workloadSummary,
    summary: r.result.summary, verification: r.result.verification, freezeRecords: r.freezeRecords, diagnoserSuggestions: r.diagnoserSuggestions.length,
    diagnoserEscalationsAccepted: r.diagnoserSuggestions.flatMap(s => s.escalationAttempts ?? []).filter(x => x.endsWith(':ACCEPTED')).length,
    rows: compactRows(r.result.rows) }));
  report.results[`inprocess_${mode}`] = { file: f, summary: r.result.summary, workload: { requests: r.workloadSummary.requests, attacks: r.workloadSummary.attacks, attackRate: r.workloadSummary.attackRate, meanGapMs: r.workloadSummary.meanGapMs, hourly: r.workloadSummary.hourlyAttackPct },
    freezes: r.freezeRecords.filter(x => x.type === 'FREEZE').length, diagnoserEscalationsAccepted: r.diagnoserSuggestions.flatMap(s => s.escalationAttempts ?? []).filter(x => x.endsWith(':ACCEPTED')).length };
}
report.commands.inprocess = `runInProcess({ seed: '${seed24}', hours: ${hours}, mode: A|B|C })`;

// 4. OS-isolated runs.
const osRuns = [
  ['os-suite-B', ['--seed', 'eval-suite:' + short, '--suite', '--suite-repeat', '2', '--mode', 'B']],
  ['os-24h-A', ['--seed', seed24, '--hours', String(hours), '--mode', 'A']],
  ['os-24h-B', ['--seed', seed24, '--hours', String(hours), '--mode', 'B']],
  ['os-24h-C', ['--seed', seed24, '--hours', String(hours), '--mode', 'C']],
  ['os-drill-preaudit', ['--seed', 'eval-drill-pre:' + short, '--hours', '4', '--mode', 'B', '--flaw', 'SKIP_RECIPIENT_BINDING', '--techniques', 'recipient_substitution,prompt_injection,malicious_tool_output']],
  ['os-drill-posteffect-repair', ['--seed', 'eval-drill-post:' + short, '--hours', '6', '--mode', 'B', '--flaw', 'SKIP_RECIPIENT_BINDING', '--no-pre-audit', '--repair', '--techniques', 'recipient_substitution,prompt_injection,replay,duplicate_execution']],
];
for (const [name, args] of osRuns) {
  if (!isRoot) { report.results[name] = { status: 'NOT VERIFIED (not root)' }; continue; }
  log('os', name);
  const out = join(OUT, name);
  const t = Date.now();
  const r = spawnSync(node, ['scripts/v2/run-isolated.mjs', ...args, '--out', out], { encoding: 'utf8', timeout: 3600_000 });
  const e = JSON.parse(readFileSync(join(out, 'run.json'), 'utf8'));
  if (e.results?.result?.rows) { e.results.result.rows = compactRows(e.results.result.rows); writeFileSync(join(out, 'run.json'), JSON.stringify(e)); }
  const R = e.results;
  const fz = R?.freezeRecords?.filter(x => x.type === 'FREEZE') ?? [];
  const viol = R?.result?.verification?.violations ?? [];
  report.results[name] = { exit: r.status, wallMs: Date.now() - t, dir: name, matrixOk: e.isolation.matrixOk, summary: R?.result?.summary, workload: R?.workloadSummary && { requests: R.workloadSummary.requests, attacks: R.workloadSummary.attacks, attackRate: R.workloadSummary.attackRate, meanGapMs: R.workloadSummary.meanGapMs },
    exfilReceived: R?.exfilReceived?.length, ssrfPositiveControl: R?.ssrfPositiveControl, aliveAfter: R?.aliveAfter,
    osProbeObtained: R?.result?.rows?.flatMap(x => x.zone?.steps ?? []).filter(s => s[1] === 'OBTAINED' || s[1] === 'ERROR').length,
    freezes: fz.map(f => ({ id: f.id, classification: f.classification, reason: f.reason, frozenAt: f.frozenAt, containmentWallMs: f.containmentWallMs, steps: f.steps })),
    detectionToContainment: viol.filter(v => v.submittedAt).map(v => ({ effectAt: v.submittedAt, freezeAt: fz[0]?.frozenAt, virtualMs: fz[0] ? fz[0].frozenAt - v.submittedAt : null, wallContainmentMs: fz[0]?.containmentWallMs })),
    effectsDuringFreeze: R?.result?.rows?.filter(x => x.duringFreeze && x.observed === 'UNAUTHORIZED_EFFECT').length, attacksDuringFreeze: R?.result?.rows?.filter(x => x.duringFreeze).length,
    repairs: R?.repairs?.map(x => ({ gates: x.gates, resumed: x.resumed, recovery: x.recovery?.checks, diagnosis: x.diagnosis, replay: x.replay?.steps?.map(s => [s.outcome, s.code, s.detail]) })), repairAgent: e.repairAgent };
  report.commands[name] = 'sudo node scripts/v2/run-isolated.mjs ' + args.map(a => /[,:]/.test(a) ? `'${a}'` : a).join(' ');
}
report.finishedAt = new Date().toISOString();
writeFileSync(join(OUT, 'V2-EVIDENCE.json'), JSON.stringify(report, null, 1));
log('wrote', join(OUT, 'V2-EVIDENCE.json'));
console.log(JSON.stringify(Object.fromEntries(Object.entries(report.results).map(([k, v]) => [k, v.summary ? { unauthorized: v.summary.unauthorizedLedgerTransfers, normal: `${v.summary.normalSettled}/${v.summary.normal}`, attacks: v.summary.attacks, fn: v.summary.falseNegatives, fp: v.summary.falsePositives, matrixOk: v.matrixOk } : (v.tally ?? v)])), null, 1));
