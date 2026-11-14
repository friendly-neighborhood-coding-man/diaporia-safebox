// Synthetic keys only. Shows that key generation does not follow a public-key symlink,
// repairs a missing public key from the private key that is already on disk, refuses a
// permissive private key, and lets concurrent callers converge on one key.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, lstatSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { layout } from '../../src/v2/launch/layout.mjs';
import { generateZoneKeys } from '../../src/v2/launch/keygen.mjs';
import { generatePrivateKey, exportPkcs8, keyIdOf } from '../../src/v2/common/crypto.mjs';

function dirs(base) {
  for (const p of ['sens', 'sup', 'pub/sens', 'pub/sup']) mkdirSync(join(base, p), { recursive: true });
  return layout(base);
}

test('public-key symlink is replaced, not followed', () => {
  const base = mkdtempSync(join(tmpdir(), 'kg-sym-'));
  const L = dirs(base);
  const canary = join(base, 'canary');
  writeFileSync(canary, 'CANARY-SECRET');
  symlinkSync(canary, L.executorPub);
  const r = generateZoneKeys(base, 'sens', '0');
  assert.equal(readFileSync(canary, 'utf8'), 'CANARY-SECRET');
  assert.equal(lstatSync(L.executorPub).isSymbolicLink(), false);
  assert.equal(readFileSync(L.executorPub, 'utf8'), r.publicKey + '\n');
  assert.equal(lstatSync(L.sensKey).isFile(), true);
  assert.equal(lstatSync(L.sensKey).mode & 0o077, 0);
  rmSync(base, { recursive: true, force: true });
});

test('a private-key symlink is refused and its target is not read as the key', () => {
  const base = mkdtempSync(join(tmpdir(), 'kg-priv-'));
  const L = dirs(base);
  const target = join(base, 'target');
  writeFileSync(target, 'NOT-A-KEY');
  symlinkSync(target, L.sensKey);
  assert.throws(() => generateZoneKeys(base, 'sens', '0'), (e) => e.code === 'KEY_PATH_SYMLINK');
  assert.equal(readFileSync(target, 'utf8'), 'NOT-A-KEY');
  rmSync(base, { recursive: true, force: true });
});

test('an existing private key with no public key is republished, not skipped', () => {
  const base = mkdtempSync(join(tmpdir(), 'kg-repair-'));
  const L = dirs(base);
  const k = generatePrivateKey();
  writeFileSync(L.sensKey, JSON.stringify({ v: 'sbx2.executor-key', synthetic: true, canary: 'SBX2-CANARY-fixed', pkcs8: exportPkcs8(k) }), { mode: 0o600 });
  const r = generateZoneKeys(base, 'sens', '0');
  assert.equal(r.publicKey, keyIdOf(k));
  assert.equal(readFileSync(L.executorPub, 'utf8'), keyIdOf(k) + '\n');
  const again = generateZoneKeys(base, 'sens', '0');
  assert.equal(again.publicKey, keyIdOf(k));
  rmSync(base, { recursive: true, force: true });
});

test('a group-readable private key is refused', () => {
  const base = mkdtempSync(join(tmpdir(), 'kg-mode-'));
  const L = dirs(base);
  const k = generatePrivateKey();
  writeFileSync(L.sensKey, JSON.stringify({ v: 'sbx2.executor-key', synthetic: true, pkcs8: exportPkcs8(k) }), { mode: 0o640 });
  chmodSync(L.sensKey, 0o640);
  assert.throws(() => generateZoneKeys(base, 'sens', '0'), (e) => e.code === 'KEY_FILE_TOO_PERMISSIVE');
  rmSync(base, { recursive: true, force: true });
});

test('concurrent sens keygen calls leave one private key and a matching public key', () => {
  const base = mkdtempSync(join(tmpdir(), 'kg-race-'));
  dirs(base);
  const kids = Array.from({ length: 8 }, () => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', 'src/v2/launch/keygen.mjs', base, 'sens', '0'], { encoding: 'utf8' }));
  for (const k of kids) assert.equal(k.status, 0, k.stderr);
  const L = layout(base);
  const raw = JSON.parse(readFileSync(L.sensKey, 'utf8'));
  const pub = readFileSync(L.executorPub, 'utf8').trim();
  const mod = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', `
    import { readFileSync } from 'node:fs';
    import { importPkcs8, keyIdOf } from './src/v2/common/crypto.mjs';
    const raw = JSON.parse(readFileSync(${JSON.stringify(L.sensKey)}, 'utf8'));
    process.stdout.write(keyIdOf(importPkcs8(raw.pkcs8)));
  `], { encoding: 'utf8' });
  assert.equal(mod.status, 0, mod.stderr);
  assert.equal(pub, mod.stdout);
  assert.equal(lstatSync(L.sensKey).mode & 0o077, 0);
  assert.ok(raw.synthetic === true);
  rmSync(base, { recursive: true, force: true });
});
