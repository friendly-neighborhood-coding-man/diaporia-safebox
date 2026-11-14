// V6 hardening P1.9 (issue #14): the offline secret scan detects planted credentials (the value is never reported) and
// the repository's lockfiles are pinned with integrity hashes. Local check, not CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { scanText, checkLock } from '../../scripts/v6/supply-chain.mjs';

test('P1.9-secrets: planted credentials are detected; the scan never returns the value', () => {
  const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' });
  const planted = [pem, 'const c = "GOCSPX-' + 'a'.repeat(28) + '";', '{"refresh_token": "1//0' + 'b'.repeat(40) + '"}', 'tok=ghp_' + 'c'.repeat(36), 'AKIA' + 'D'.repeat(16), '{"client_secret":"' + 'e'.repeat(24) + '"}'];
  for (const t of planted) { const f = scanText(t); assert.ok(f.length >= 1, 'not detected: ' + t.slice(0, 12)); assert.ok(!JSON.stringify(f).includes(t.slice(8, 30)), 'value leaked in the report'); }
  assert.deepEqual(scanText("assert.throws(() => wr.append({ note: '-----BEGIN PRIVATE KEY-----' }))"), [], 'a header mentioned in a test is not a key');
});

test('P1.9-locks: both lockfiles are v3, every package has an integrity hash, direct dependencies are pinned exactly', () => {
  for (const p of ['package-lock.json', 'integrations/external-interactor/package-lock.json']) assert.deepEqual(checkLock(p).problems, [], p);
});
