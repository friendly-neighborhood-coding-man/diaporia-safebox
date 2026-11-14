// OS-level probe (post-video hardening, Mission 1). Needs root to start the probe as a second uid; skipped otherwise.
// The slot is owned by the verifier uid (root here) with no group/other write, under a 0755 parent. A process running
// as uid 65534 (nobody) makes NON-DESTRUCTIVE access attempts on MOCK files (rename, in-place write, create, symlink,
// chmod) and, concurrently with verifySlot calls, the same swap-and-swap-back rename loop used in the race research.
// Expected: every attempt fails with EACCES/EPERM and every verifySlot call succeeds on an unchanged slot.
// Negative control: the same probe against a subdirectory the probe uid owns succeeds, and verifySlot with expectUid
// refuses that slot before trusting it. This is evidence about Linux file permissions for one slot in this container;
// it is NOT evidence of a separated SSTP deployment (no controller, launcher or app uid exists; see THREAT-MODEL).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, realpathSync, rmSync, chownSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { verifySlot } from '../../src/package/install.mjs';

const PROBE_UID = 65534;
const isRoot = process.getuid?.() === 0;
const sha = (b) => createHash('sha256').update(b).digest('hex');
const GEN = Buffer.from('genuine\n');

function world(t) {
  const d = realpathSync(mkdtempSync('/tmp/sstp-os-')); chmodSync(d, 0o755); t.after(() => rmSync(d, { recursive: true, force: true }));
  const slot = join(d, 'slot'); mkdirSync(join(slot, 'sub'), { recursive: true, mode: 0o755 }); chmodSync(slot, 0o755); chmodSync(join(slot, 'sub'), 0o755);
  for (const f of ['a.mjs', 'sub/x.mjs']) { writeFileSync(join(slot, f), GEN); chmodSync(join(slot, f), 0o644); }
  const scratch = join(d, 'probe'); mkdirSync(scratch); chownSync(scratch, PROBE_UID, PROBE_UID); // the probe's own dir
  const manifest = { files: ['a.mjs', 'sub/x.mjs'].map(path => ({ path, sha256: sha(GEN), mode: 0o644 })) };
  return { d, slot, scratch, manifest };
}
const PROBE = `const fs = require('fs'); const [slot, scratch] = process.argv.slice(1); const r = {};
  const tryIt = (k, f) => { try { f(); r[k] = 'ALLOWED'; } catch (e) { r[k] = e.code; } };
  tryIt('rename sub/ out', () => fs.renameSync(slot + '/sub', scratch + '/aside'));
  tryIt('rename a.mjs out', () => fs.renameSync(slot + '/a.mjs', scratch + '/a'));
  tryIt('open a.mjs for write', () => fs.closeSync(fs.openSync(slot + '/a.mjs', 'r+')));
  tryIt('create sub/extra', () => fs.writeFileSync(slot + '/sub/extra', 'x'));
  tryIt('symlink in slot', () => fs.symlinkSync('/etc/hostname', slot + '/link'));
  tryIt('chmod a.mjs', () => fs.chmodSync(slot + '/a.mjs', 0o666));
  tryIt('rename slot itself', () => fs.renameSync(slot, scratch + '/slot'));
  process.stdout.write(JSON.stringify(r));`;

test('a second uid cannot rename, rewrite, create, link or chmod anything in a protected slot', { skip: !isRoot && 'NOT_RUN: needs root to start a second uid' }, (t) => {
  const { slot, scratch, manifest } = world(t);
  const r = spawnSync(process.execPath, ['-e', PROBE, slot, scratch], { uid: PROBE_UID, gid: PROBE_UID, cwd: scratch, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const res = JSON.parse(r.stdout);
  for (const [k, v] of Object.entries(res)) assert.ok(v === 'EACCES' || v === 'EPERM', `${k}: ${v}`);
  assert.equal(verifySlot(slot, manifest, { expectUid: 0 }).files, 2);
  t.diagnostic(JSON.stringify(res));
});

test('a concurrent swap-and-swap-back loop run as a second uid never gets a rename in; verifySlot succeeds every time', { skip: !isRoot && 'NOT_RUN: needs root to start a second uid' }, async (t) => {
  const { slot, scratch, manifest } = world(t);
  const loop = `const fs = require('fs'); const [s, a] = process.argv.slice(1); let ok = 0, denied = 0; const end = Date.now() + 3000;
    while (Date.now() < end) { try { fs.renameSync(s, a); ok++; fs.renameSync(a, s); } catch (e) { denied++; } }
    process.stdout.write(JSON.stringify({ ok, denied }));`;
  const atk = spawn(process.execPath, ['-e', loop, join(slot, 'sub'), join(scratch, 'aside')], { uid: PROBE_UID, gid: PROBE_UID, cwd: scratch });
  let out = ''; atk.stdout.on('data', (b) => { out += b; });
  const done = new Promise((res) => atk.on('exit', res));
  let calls = 0, fails = 0; const end = Date.now() + 2500;
  while (Date.now() < end) { try { verifySlot(slot, manifest, { expectUid: 0 }); } catch { fails++; } calls++; await new Promise(setImmediate); }
  await done;
  const a = JSON.parse(out);
  t.diagnostic(JSON.stringify({ verifyCalls: calls, verifyFailures: fails, probeRenamesSucceeded: a.ok, probeRenamesDenied: a.denied }));
  assert.equal(a.ok, 0); assert.ok(a.denied > 0); assert.equal(fails, 0); assert.ok(calls > 0);
  assert.equal(readFileSync(join(slot, 'sub/x.mjs')).toString(), 'genuine\n');
});

test('negative control: a subdirectory owned by the second uid is writable by it, and verifySlot(expectUid) refuses that slot', { skip: !isRoot && 'NOT_RUN: needs root to start a second uid' }, (t) => {
  const { slot, scratch, manifest } = world(t);
  chownSync(join(slot, 'sub'), PROBE_UID, PROBE_UID);
  const r = spawnSync(process.execPath, ['-e', `require('fs').writeFileSync(process.argv[1], 'x'); require('fs').unlinkSync(process.argv[1]);`, join(slot, 'sub', 'probe-created')], { uid: PROBE_UID, gid: PROBE_UID, cwd: scratch, encoding: 'utf8' });
  assert.equal(r.status, 0, 'the probe uid can write its own directory: ' + r.stderr);
  assert.throws(() => verifySlot(slot, manifest, { expectUid: 0 }), (e) => e.code === 'SLOT_WRONG_OWNER');
  chownSync(join(slot, 'sub'), 0, 0); chownSync(slot, PROBE_UID, PROBE_UID);
  assert.throws(() => verifySlot(slot, manifest, { expectUid: 0 }), (e) => e.code === 'SLOT_PATH_NOT_PROTECTED');
});
