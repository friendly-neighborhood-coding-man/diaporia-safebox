// OS-level isolation: runs the real multi-principal deployment (separate uids, no capabilities, no_new_privs,
// General Zone in an empty network namespace). Requires Linux + root + setpriv/unshare; otherwise SKIPPED and
// OS isolation must be reported as NOT VERIFIED for that environment.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const capable = !process.env.SBX2_NESTED_REGRESSION && process.platform === 'linux' && process.getuid?.() === 0 && ['setpriv', 'unshare', 'useradd'].every(b => spawnSync('sh', ['-c', 'command -v ' + b]).status === 0);
const skip = capable ? false : 'OS isolation NOT VERIFIED here (needs Linux + root + setpriv/unshare/useradd)';
const launcher = new URL('../../scripts/v2/run-isolated.mjs', import.meta.url).pathname;
const run = (args) => { const out = mkdtempSync(join(tmpdir(), 'sbx2-os-')); const r = spawnSync(process.execPath, [launcher, ...args, '--out', out], { encoding: 'utf8', timeout: 600_000 }); return { r, e: JSON.parse(readFileSync(join(out, 'run.json'), 'utf8')) }; };

test('OS: access matrix + all 24 techniques through real sockets/files/signals/network', { skip }, () => {
  const { r, e } = run(['--seed', 'os-test-suite', '--suite', '--mode', 'B']);
  assert.equal(r.status, 0, r.stderr.slice(-2000));
  assert.equal(e.isolation.matrixOk, true, JSON.stringify(e.isolation.matrix.filter(m => m.ok === false)));
  const s = e.results.result.summary;
  assert.equal(s.unauthorizedLedgerTransfers, 0); assert.equal(s.normalSuccessRate, 1); assert.equal(s.duplicateEffects, 0);
  assert.equal(e.results.exfilReceived.length, 0); assert.equal(e.results.ssrfPositiveControl, true);
  assert.deepEqual(e.results.aliveAfter, { ledger: 'alive(EPERM)', sensitive: 'alive(EPERM)', watchdog: true });
  const osSteps = e.results.result.rows.filter(x => x.label === 'attack').flatMap(x => x.zone.steps).filter(st => st.outcome === 'OBTAINED' || st.outcome === 'ERROR');
  assert.deepEqual(osSteps, [], 'no OS-level probe obtained anything');
  assert.equal(e.results.freezeRecords.length, 0);
});

test('OS: containment + automated repair drill (injected flaw, post-effect detection) resumes only after all gates pass', { skip }, () => {
  const { r, e } = run(['--seed', 'os-test-drill', '--hours', '3', '--mode', 'B', '--flaw', 'SKIP_RECIPIENT_BINDING', '--no-pre-audit', '--repair', '--techniques', 'recipient_substitution,prompt_injection']);
  assert.equal(r.status, 0, r.stderr.slice(-2000));
  const R = e.results;
  assert.ok(R.freezeRecords.some(f => f.type === 'FREEZE' && f.classification === 'CONFIRMED_BREACH'));
  const rep = R.repairs.find(x => x.resumed);
  assert.ok(rep, JSON.stringify(R.repairs.map(x => x.gates)));
  assert.deepEqual(rep.gates, { patchApplied: true, replayDenied: true, mutationsDenied: true, regressionGreen: true });
  assert.ok(R.result.summary.unauthorizedLedgerTransfers <= 1, 'at most the single pre-detection drill effect');
  assert.equal(R.result.rows.filter(x => x.duringFreeze && x.observed === 'UNAUTHORIZED_EFFECT').length, 0);
  assert.equal(R.sensitiveState.injectFlaw, null);
});
