// V6 hardening P1.9 (issue #14): the offline secret scan detects planted credentials (the value is never reported) and
// the repository's lockfiles are pinned with integrity hashes. Local check, not CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { scanText, checkLock } from '../../scripts/v6/supply-chain.mjs';

test('P1.9-secrets: planted credentials are detected; the scan never returns the value', () => {
  const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' });
  const planted = [pem, 'const c = "GOCSPX-' + 'a'.repeat(28) + '";', '{"refresh_' + 'token": "1//0' + 'b'.repeat(40) + '"}', 'tok=ghp_' + 'c'.repeat(36), 'AKIA' + 'D'.repeat(16), '{"client_' + 'secret":"' + 'e'.repeat(24) + '"}'];
  for (const t of planted) { const f = scanText(t); assert.ok(f.length >= 1, 'not detected: ' + t.slice(0, 12)); assert.ok(!JSON.stringify(f).includes(t.slice(8, 30)), 'value leaked in the report'); }
  assert.deepEqual(scanText("assert.throws(() => wr.append({ note: '-----BEGIN PRIVATE KEY-----' }))"), [], 'a header mentioned in a test is not a key');
});

test('P1.9-locks: both lockfiles are v3, every package has an integrity hash, direct dependencies are pinned exactly', () => {
  for (const p of ['package-lock.json', 'integrations/external-interactor/package-lock.json']) assert.deepEqual(checkLock(p).problems, [], p);
});

// Final delta review (2106493, LOW): PEMs written as concatenated string literals, legacy encrypted RSA, DSA and PGP
// key headers, and JWK private keys were missed.
test('P1.9-secrets (review): key material in source-literal, legacy-encrypted, DSA, PGP and JWK form is detected', () => {
  const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' });
  const b64 = pem.split('\n')[1];
  const cases = {
    concatenated: pem.trim().split('\n').map((l) => `  '${l}\\n' +`).join('\n') + " '';",
    legacyEncrypted: `-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n${b64}\n-----END RSA PRIVATE KEY-----`,
    dsa: `-----BEGIN DSA PRIVATE KEY-----\n${b64}\n-----END DSA PRIVATE KEY-----`,
    pgp: `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${b64}\n-----END PGP PRIVATE KEY BLOCK-----`,
    jwk: `{"kty":"EC","crv":"P-256","x":"${'x'.repeat(43)}","y":"${'y'.repeat(43)}","d":"${'D'.repeat(43)}"}`,
  };
  for (const [k, t] of Object.entries(cases)) assert.ok(scanText(t).length >= 1, 'not detected: ' + k);
  assert.deepEqual(scanText("const h = '-----BEGIN PRIVATE KEY-----'; // header only"), [], 'a header mentioned alone is not a key');
});
