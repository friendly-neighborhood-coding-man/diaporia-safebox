import test from 'node:test';
import assert from 'node:assert/strict';
import { readTar, writeTar, PackageError } from '../../src/package/tar.mjs';
import { openPackage, MANIFEST_NAME } from '../../src/package/manifest.mjs';
import { canon } from '../../src/common/crypto.mjs';
import { makePackage } from './helpers.mjs';

const rejects = (fn, code) => assert.throws(fn, (e) => e instanceof PackageError && e.code === code, `expected ${code}`);
const one = (e) => writeTar([e]);

test('well-formed package round-trips', () => {
  const { bytes } = makePackage({ version: 3 });
  const p = openPackage(bytes);
  assert.equal(p.manifest.version, 3);
  assert.deepEqual(p.files.map(f => f.path).sort(), ['lib/util.mjs', 'main.mjs']);
});

test('tar reader rejects non-regular entries and unsafe paths', () => {
  rejects(() => readTar(one({ name: 'x', type: '2', linkname: '/etc/passwd' })), 'ENTRY_SYMLINK');
  rejects(() => readTar(one({ name: 'x', type: '1', linkname: 'main.mjs' })), 'ENTRY_HARDLINK');
  rejects(() => readTar(one({ name: 'dev', type: '3' })), 'ENTRY_TYPE_FORBIDDEN');
  rejects(() => readTar(one({ name: 'fifo', type: '6' })), 'ENTRY_TYPE_FORBIDDEN');
  rejects(() => readTar(one({ name: 'pax', type: 'x', data: 'a' })), 'ENTRY_TYPE_FORBIDDEN');
  rejects(() => readTar(one({ name: '../x' })), 'PATH_TRAVERSAL');
  rejects(() => readTar(one({ name: 'a/../../x' })), 'PATH_TRAVERSAL');
  rejects(() => readTar(one({ name: 'x', prefix: '..' })), 'PATH_TRAVERSAL');
  rejects(() => readTar(one({ name: '/etc/x' })), 'PATH_ABSOLUTE');
  rejects(() => readTar(one({ name: './x' })), 'PATH_NOT_NORMALIZED');
  rejects(() => readTar(one({ name: 'a//x' })), 'PATH_NOT_NORMALIZED');
  rejects(() => readTar(one({ name: 'a\\x' })), 'PATH_BAD_CHAR');
  rejects(() => readTar(one({ name: '.hidden' })), 'PATH_BAD_CHAR');
  rejects(() => readTar(one({ name: 'x', mode: 0o4755 })), 'MODE_FORBIDDEN');
  rejects(() => readTar(one({ name: 'x', mode: 0o666 })), 'MODE_FORBIDDEN');
  rejects(() => readTar(writeTar([{ name: 'A' }, { name: 'a' }])), 'ENTRY_DUPLICATE');
  rejects(() => readTar(writeTar([{ name: 'a', data: 'x' }, { name: 'a/b' }])), 'PATH_FILE_AS_DIR');
});

test('tar reader enforces bounds and structure', () => {
  rejects(() => readTar(writeTar(Array.from({ length: 257 }, (_, i) => ({ name: `f${i}` })))), 'TOO_MANY_ENTRIES');
  rejects(() => readTar(writeTar([{ name: 'big', data: Buffer.alloc((4 << 20) + 1) }])), 'FILE_TOO_LARGE');
  rejects(() => readTar(Buffer.alloc((8 << 20) + 512)), 'ARCHIVE_TOO_LARGE');
  const ok = writeTar([{ name: 'a', data: 'hello' }]);
  rejects(() => readTar(ok.subarray(0, 512)), 'TAR_TRUNCATED');
  rejects(() => readTar(ok.subarray(0, 700)), 'TAR_MISALIGNED');
  const bad = Buffer.from(ok); bad[10] ^= 1; rejects(() => readTar(bad), 'TAR_BAD_CHECKSUM');
  const trail = Buffer.concat([ok, Buffer.alloc(512, 1)]); rejects(() => readTar(trail), 'TAR_TRAILING_DATA');
});

test('manifest must be first, canonical, complete and closed', () => {
  rejects(() => openPackage(makePackage({ mutate: (e) => [e[1], e[0], ...e.slice(2)] }).bytes), 'MANIFEST_NOT_FIRST');
  rejects(() => openPackage(makePackage({ mutate: (e) => { e[0].data = Buffer.from(JSON.stringify(JSON.parse(e[0].data), null, 1)); } }).bytes), 'MANIFEST_NOT_CANONICAL');
  rejects(() => openPackage(makePackage({ mutate: (e) => { const m = JSON.parse(e[0].data); m.hooks = { postinstall: 'x' }; e[0].data = canon(m); } }).bytes), 'MANIFEST_UNKNOWN_OR_MISSING_FIELD');
  rejects(() => openPackage(makePackage({ mutate: (e) => { const m = JSON.parse(e[0].data); m.policy = { budget: '1' }; e[0].data = canon(m); } }).bytes), 'MANIFEST_UNKNOWN_OR_MISSING_FIELD');
  rejects(() => openPackage(makePackage({ mutate: (e) => { e[2].data = Buffer.from('changed'); } }).bytes), 'MANIFEST_DIGEST_MISMATCH');
  rejects(() => openPackage(makePackage({ mutate: (e) => [...e, { name: 'extra.mjs', data: 'x' }] }).bytes), 'MANIFEST_FILE_SET_MISMATCH');
  rejects(() => openPackage(makePackage({ mutate: (e) => { e[2].mode = 0o755; } }).bytes), 'MANIFEST_MODE_MISMATCH');
  rejects(() => openPackage(makePackage({ files: [{ path: 'other.mjs', data: Buffer.from('x') }] }).bytes), 'MANIFEST_ENTRY_MISSING');
  rejects(() => openPackage(makePackage({ version: 0 }).bytes), 'MANIFEST_VERSION');
  rejects(() => openPackage(makePackage({ authoritySchema: { min: 2, max: 1 } }).bytes), 'MANIFEST_SCHEMA_RANGE');
  rejects(() => openPackage(makePackage({ mutate: (e) => [...e, { name: MANIFEST_NAME.toLowerCase(), data: 'x' }] }).bytes), 'ENTRY_DUPLICATE');
});

test('property: random single-byte corruption never yields an accepted package with different content', () => {
  const { bytes, manifest } = makePackage({ version: 5 });
  let seed = 12345; const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff);
  let accepted = 0;
  for (let i = 0; i < 3000; i++) {
    const b = Buffer.from(bytes); const pos = rnd() % b.length; const v = rnd() & 0xff; if (b[pos] === v) continue; b[pos] = v;
    try { const p = openPackage(b); accepted++; assert.deepEqual(p.manifest, manifest); for (const f of p.files) assert.equal(f.data.length, manifest.files.find(x => x.path === f.path).size); }
    catch (e) { assert.ok(e instanceof PackageError, `unexpected ${e}`); }
  }
  // Accepted corruptions can only be in ignored header bytes (mtime, uid, gname...), never in content or manifest.
  assert.ok(accepted < 3000);
});
