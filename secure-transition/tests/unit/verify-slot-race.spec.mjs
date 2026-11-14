// Regression: verifySlot must not accept a slot when a path check and a later
// path read can observe different directory entries. The preload swaps the
// checked file for a symlink to the same bytes after the first no-follow stat.
// A check-then-read verifier returns success and leaves the symlink. An
// open-then-fstat verifier either rejects the symlink or never stats the path
// before reading, so the slot entry stays the regular file that was hashed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../../src/common/crypto.mjs';
import { verifySlot } from '../../src/package/install.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const BYTES = Buffer.from('export const VERSION = 1;\n');

function manifestFor(data, mode = 0o644) {
  return { files: [{ path: 'main.mjs', sha256: sha256(data), size: data.length, mode }] };
}

test('verifySlot rejects a symlink that appears between the path check and the read', () => {
  const cc = spawnSync('gcc', ['-shared', '-fPIC', '-o', join(tmpdir(), 'sstp-toctou.so'), join(here, 'toctou-preload.c'), '-ldl']);
  assert.equal(cc.status, 0, cc.stderr?.toString());
  const d = mkdtempSync(join(tmpdir(), 'sstp-slot-'));
  const slot = join(d, 'B');
  mkdirSync(slot);
  const file = join(slot, 'main.mjs');
  const twin = join(d, 'twin');
  writeFileSync(file, BYTES, { mode: 0o644 });
  writeFileSync(twin, BYTES);
  chmodSync(file, 0o644);
  const child = `
    import { lstatSync } from 'node:fs';
    import { verifySlot } from ${JSON.stringify(join(here, '../../src/package/install.mjs'))};
    const slot = ${JSON.stringify(slot)};
    const file = ${JSON.stringify(file)};
    const manifest = ${JSON.stringify(manifestFor(BYTES))};
    let error = null;
    try { verifySlot(slot, manifest); } catch (e) { error = { code: e.code, message: e.message }; }
    delete process.env.TOCTOU_PATH;
    const st = lstatSync(file);
    process.stdout.write(JSON.stringify({ error, symlink: st.isSymbolicLink(), file: st.isFile() }));
  `;
  const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', child], {
    env: {
      ...process.env,
      LD_PRELOAD: join(tmpdir(), 'sstp-toctou.so'),
      TOCTOU_PATH: file,
      TOCTOU_DEST: twin,
    },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  // Secure outcome: the verifier failed closed, or it hashed the regular file and left that regular file in place.
  const closed = out.error && (out.error.code === 'SLOT_CONTAINS_SYMLINK' || out.error.code === 'SLOT_CHANGED_DURING_READ');
  const consistent = !out.error && out.file === true && out.symlink === false;
  assert.ok(closed || consistent, JSON.stringify(out));
  assert.equal(out.symlink, false, 'a successful verify must not leave a symlink at the hashed path: ' + JSON.stringify(out));
});

test('verifySlot rejects a planted symlink without a race', () => {
  const d = mkdtempSync(join(tmpdir(), 'sstp-link-'));
  const slot = join(d, 'B');
  mkdirSync(slot);
  writeFileSync(join(d, 'outside'), BYTES);
  symlinkSync(join(d, 'outside'), join(slot, 'main.mjs'));
  assert.throws(() => verifySlot(slot, manifestFor(BYTES)), (e) => e.code === 'SLOT_CONTAINS_SYMLINK');
  rmSync(d, { recursive: true, force: true });
});
