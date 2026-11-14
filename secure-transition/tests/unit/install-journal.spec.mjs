import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, writeFileSync, readFileSync, existsSync, appendFileSync, chmodSync, lstatSync, renameSync, unlinkSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { installToSlot, verifySlot, readCheckedFile } from '../../src/package/install.mjs';
import { openPackage } from '../../src/package/manifest.mjs';
import { Journal, readJournal } from '../../src/common/journal.mjs';
import { makePackage, tmp } from './helpers.mjs';

const rejects = (fn, code) => assert.throws(fn, (e) => e.code === code, `expected ${code}`);

test('install into allow-listed slot, read back, verify', (t) => {
  const d = tmp(t); const slot = join(d, 'B'); mkdirSync(slot);
  const pkg = openPackage(makePackage({ version: 2 }).bytes);
  const r = installToSlot(slot, pkg, { allowList: [slot] });
  assert.equal(r.files, 2);
  assert.match(readFileSync(join(slot, 'main.mjs'), 'utf8'), /VERSION = 2/);
});

test('destination allow-list, symlinked slot and planted files', (t) => {
  const d = tmp(t); const slot = join(d, 'B'); mkdirSync(slot); const pkg = openPackage(makePackage().bytes);
  rejects(() => installToSlot(join(d, 'C'), pkg, { allowList: [slot] }), 'SLOT_NOT_ALLOWLISTED');
  const outside = join(d, 'outside'); mkdirSync(outside); const link = join(d, 'L'); symlinkSync(outside, link);
  rejects(() => installToSlot(link, pkg, { allowList: [link] }), 'SLOT_NOT_A_DIRECTORY');
  // A symlink planted in the slot (e.g. lib -> outside) is removed by the wipe; nothing is written outside.
  symlinkSync(outside, join(slot, 'lib')); writeFileSync(join(slot, 'stale'), 'x');
  installToSlot(slot, pkg, { allowList: [slot] });
  assert.equal(existsSync(join(outside, 'util.mjs')), false);
  assert.equal(existsSync(join(slot, 'stale')), false);
});

test('verifySlot detects tampering after install', (t) => {
  const d = tmp(t); const slot = join(d, 'B'); mkdirSync(slot); const pkg = openPackage(makePackage().bytes);
  installToSlot(slot, pkg, { allowList: [slot] });
  appendFileSync(join(slot, 'main.mjs'), '//x'); rejects(() => verifySlot(slot, pkg.manifest), 'SLOT_DIGEST_MISMATCH');
  installToSlot(slot, pkg, { allowList: [slot] });
  writeFileSync(join(slot, 'extra'), 'x'); rejects(() => verifySlot(slot, pkg.manifest), 'SLOT_FILE_SET_MISMATCH');
  installToSlot(slot, pkg, { allowList: [slot] });
  chmodSync(join(slot, 'main.mjs'), 0o666); rejects(() => verifySlot(slot, pkg.manifest), 'SLOT_WRITABLE_BY_OTHERS');
  installToSlot(slot, pkg, { allowList: [slot] });
  rejects(() => verifySlot(slot, pkg.manifest, { expectUid: 4242 }), 'SLOT_WRONG_OWNER');
});

test('journal: hash chain, torn tail dropped, mid-file tamper detected', (t) => {
  const d = tmp(t); const p = join(d, 'j.log');
  const j = new Journal(p); j.append('IDLE'); j.append('DOWNLOADED', { a: 1 }); j.append('VERIFIED');
  assert.equal(new Journal(p).records.length, 3);
  appendFileSync(p, '{"seq":3,"prev":"tor');           // power loss mid-write
  const j2 = new Journal(p); assert.equal(j2.tornOnOpen, true); assert.equal(j2.records.length, 3);
  j2.append('OWNER_AUTHORIZED'); assert.equal(new Journal(p).records.length, 4);
  const lines = readFileSync(p, 'utf8').split('\n'); const r1 = JSON.parse(lines[1]); r1.data.a = 2; lines[1] = JSON.stringify(r1);
  writeFileSync(p, lines.join('\n'));
  const r = readJournal(p); assert.equal(r.tampered, true); assert.equal(r.records.length, 1);
  assert.throws(() => new Journal(p).append('X'), /JOURNAL_TAMPERED/);
});

// CodeQL js/file-system-race (install.mjs verifySlot): the object read is the object that was lstat-checked.
test('verifySlot race: a file swapped for a symlink / another file / a FIFO after the lstat is refused, never read by path', (t) => {
  const d = tmp(t); const p = join(d, 'main.mjs'); writeFileSync(p, 'genuine'); chmodSync(p, 0o644);
  const lst = lstatSync(p);
  assert.equal(readCheckedFile(p, 'main.mjs', lst).data.toString(), 'genuine');
  // symlink swapped in between lstat and read (it points at a byte-identical copy, so a digest check alone would pass)
  const copy = join(d, 'copy'); writeFileSync(copy, 'genuine'); chmodSync(copy, 0o644);
  renameSync(p, join(d, 'orig')); symlinkSync(copy, p); // keep the checked inode alive so it cannot be reused below
  rejects(() => readCheckedFile(p, 'main.mjs', lst), 'SLOT_CONTAINS_SYMLINK');
  // a different regular file renamed over the path (same bytes, different inode)
  unlinkSync(p); const other = join(d, 'other'); writeFileSync(other, 'genuine'); chmodSync(other, 0o644); renameSync(other, p);
  rejects(() => readCheckedFile(p, 'main.mjs', lst), 'SLOT_CHANGED_DURING_VERIFY');
  // a FIFO swapped in must not block the verifier
  if (process.platform !== 'win32') {
    unlinkSync(p); execFileSync('mkfifo', [p]);
    rejects(() => readCheckedFile(p, 'main.mjs', lst), 'SLOT_CHANGED_DURING_VERIFY');
  }
  // the fd-side mode / owner checks still apply
  unlinkSync(p); writeFileSync(p, 'genuine'); chmodSync(p, 0o666); const l2 = lstatSync(p);
  rejects(() => readCheckedFile(p, 'main.mjs', l2), 'SLOT_WRITABLE_BY_OTHERS');
  chmodSync(p, 0o644); rejects(() => readCheckedFile(p, 'main.mjs', lstatSync(p), { expectUid: 4242 }), 'SLOT_WRONG_OWNER');
});
