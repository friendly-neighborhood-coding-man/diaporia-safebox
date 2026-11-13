// Deployment invariants (D1-D4) and the OS privilege matrix for the V3 principals.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkDeployment } from '../../scripts/v3/check-deployment.mjs';

const fx = (n) => JSON.parse(readFileSync(new URL(`./fixtures/${n}`, import.meta.url), 'utf8'));

test('deployment: reviewed hash + FunctionCall-only keys passes', () => {
  assert.deepEqual(checkDeployment(fx('deploy-good.json'), { expectCodeHash: 'HASH_REVIEWED' }), { ok: true, violations: [] });
});

test('deployment: FullAccess, all-methods, re-init, foreign receiver and code-hash drift are all reported', () => {
  const r = checkDeployment(fx('deploy-bad.json'), { expectCodeHash: 'HASH_REVIEWED' });
  assert.equal(r.ok, false);
  assert.deepEqual(r.violations.map(v => v.code).sort(), ['D1_FULL_ACCESS_KEY', 'D2_ALL_METHODS', 'D2_FOREIGN_RECEIVER', 'D2_METHOD_NOT_ALLOWED', 'D2_METHOD_NOT_ALLOWED', 'D3_CODE_HASH_MISMATCH'].sort());
});

test('deployment: missing expected hash and implicit accounts fail closed', () => {
  const r = checkDeployment({ accountId: 'a'.repeat(64), keys: [] });
  assert.deepEqual(r.violations.map(v => v.code).sort(), ['D3_NO_EXPECTED_HASH', 'D4_IMPLICIT_ACCOUNT']);
});

const capable = process.platform === 'linux' && process.getuid?.() === 0 && ['setpriv', 'unshare', 'useradd'].every(b => spawnSync('sh', ['-c', 'command -v ' + b]).status === 0);
test('OS: V3 principal privilege matrix (root / recovery / vault / ledger / general zone)', { skip: capable ? false : 'OS isolation NOT VERIFIED here (needs Linux + root)' }, () => {
  const out = mkdtempSync(join(tmpdir(), 'sbx3-os-'));
  const r = spawnSync(process.execPath, [new URL('../../scripts/v3/os-matrix.mjs', import.meta.url).pathname, '--out', out], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const { summary, matrix } = JSON.parse(readFileSync(join(out, 'os-matrix.json'), 'utf8'));
  assert.equal(summary.violations, 0);
  assert.ok(summary.genNetwork.startsWith('DENIED'));
  // positive controls: every zone can use its own state (the probe is not trivially denied everywhere)
  for (const z of ['root', 'recov', 'vault', 'ledger', 'gen']) assert.ok(matrix.some(m => m.principal === 'sbx3-' + z && m.target.startsWith(z + '/') && m.what === 'write' && m.outcome === 'OBTAINED'), z);
  // the AI zone reaches no secret
  assert.deepEqual(matrix.filter(m => m.principal === 'sbx3-gen' && m.outcome === 'OBTAINED' && !m.target.startsWith('gen/') && m.target !== 'trusted/pinned-public-keys.json' && m.target !== 'proc:gen'), []);
});
