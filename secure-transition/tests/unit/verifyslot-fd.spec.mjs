// Post-video hardening, Mission 1: descriptor-relative verifySlot. Deterministic regressions for the PR #27 races
// (independent evaluation in PR #31) and for the protected-path precondition. MOCK files only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, realpathSync, rmSync, symlinkSync, renameSync, chownSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { verifySlot, assertProtectedPath, fdRelativeSupported } from '../../src/package/install.mjs';

const ST = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const sha = (b) => createHash('sha256').update(b).digest('hex');
const rejects = (fn, code) => assert.throws(fn, (e) => { assert.equal(e.code, code, e.message); return true; });
const GEN = Buffer.from('genuine\n');
function slotWorld(t) {
  const d = realpathSync(mkdtempSync(join(tmpdir(), 'sstp-fd-'))); t.after(() => rmSync(d, { recursive: true, force: true }));
  const slot = join(d, 'slot'); mkdirSync(join(slot, 'sub'), { recursive: true });
  for (const f of ['a.mjs', 'sub/x.mjs']) { writeFileSync(join(slot, f), GEN); chmodSync(join(slot, f), 0o644); }
  const manifest = { files: ['a.mjs', 'sub/x.mjs'].map(path => ({ path, sha256: sha(GEN), mode: 0o644 })) };
  return { d, slot, manifest };
}

test('fd-relative verification is available on this Linux host', (t) => {
  assert.equal(fdRelativeSupported(), true);
  const { slot, manifest } = slotWorld(t);
  assert.deepEqual(verifySlot(slot, manifest), { files: 2 });
});

test('exhaustive interposition: no attacker mutation made during the walk yields SUCCESS with a foreign slot (PR #27 had 264)', () => {
  const r = spawnSync(process.execPath, [join(ST, 'tests/research/verifyslot-exhaustive.mjs'), ST], { encoding: 'utf8', timeout: 300_000 });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.control, 'SUCCESS');
  for (const [name, s] of Object.entries(out.summary)) {
    assert.ok(s.fullyFired > 0, `${name}: attack never fired`);
    assert.equal(s.bypassDuringWalk, 0, `${name}: ${JSON.stringify(s.bypassAt)}`);
  }
  // Directory swap-and-swap-back through a symlink is never accepted, anywhere in the call.
  assert.equal(out.summary['P2 sub/ swap-and-swap-back with a SYMLINK to the genuine twin'].success, 0);
  // Residual, measured: the remaining in-call successes all need the mutation to land after the final check that
  // covers the mutated object (closing window); they are verify-then-use, not walk races.
  for (const s of Object.values(out.summary)) assert.equal(s.inCallBypass, s.bypassInClosingWindow);
  // Renames, swaps, links, symlinks and new entries: refused unless the mutation lands in the last two inspecting calls
  // (the slot-path check and the root directory's check close the pass, in that order; an ancestor swap-back after
  // the slot-path check falls in that window). Content and mode changes
  // (A3 in-place rewrite, A7 chmod, A8 rewrite + utimes) are bounded only by that file's own entry re-check, and only
  // where ctime is fine-grained; a write through a dirty shared mapping is not detected at all (review F1,
  // tests/research/review/mmap_bypass.mjs). None of these is a content guarantee against a slot writer.
  const CONTENT = ['A3', 'A7', 'A8'];
  for (const [name, s] of Object.entries(out.summary)) {
    if (CONTENT.some(c => name.startsWith(c))) continue;
    // A new entry inside sub/ is bounded by sub/'s own final check, after which the slot-path and root checks (4 calls)
    // remain; everything in the root or above it is bounded by the last two inspecting calls.
    const window = name.startsWith('A4') ? 4 : 2;
    for (const b of s.bypassAt ?? []) {
      const last = Math.max(...b.split(':')[0].split('+').map(Number));
      assert.ok(last > out.lastCheckCall - window, `${name}: mutation before call ${last} (last inspecting call ${out.lastCheckCall})`);
    }
  }
});

test('static cases still refused: symlinked subdirectory, symlinked file, extra file, tampered bytes', (t) => {
  { const { d, slot, manifest } = slotWorld(t); const twin = join(d, 'twin'); mkdirSync(twin); writeFileSync(join(twin, 'x.mjs'), GEN); chmodSync(join(twin, 'x.mjs'), 0o644);
    renameSync(join(slot, 'sub'), join(d, 'old')); symlinkSync(twin, join(slot, 'sub')); rejects(() => verifySlot(slot, manifest), 'SLOT_CONTAINS_SYMLINK'); }
  { const { d, slot, manifest } = slotWorld(t); writeFileSync(join(d, 'g'), GEN); renameSync(join(slot, 'a.mjs'), join(d, 'o')); symlinkSync(join(d, 'g'), join(slot, 'a.mjs'));
    rejects(() => verifySlot(slot, manifest), 'SLOT_CONTAINS_SYMLINK'); }
  { const { slot, manifest } = slotWorld(t); writeFileSync(join(slot, 'sub/extra'), 'x'); chmodSync(join(slot, 'sub/extra'), 0o644); rejects(() => verifySlot(slot, manifest), 'SLOT_FILE_SET_MISMATCH'); }
  { const { slot, manifest } = slotWorld(t); writeFileSync(join(slot, 'sub/x.mjs'), 'EVIL!!!\n'); rejects(() => verifySlot(slot, manifest), 'SLOT_DIGEST_MISMATCH'); }
});

test('protected path: slot and ancestors must be unwritable by others (sticky ancestors allowed), owned by root or expectUid', (t) => {
  const { d, slot, manifest } = slotWorld(t);
  const uid = process.getuid();
  chmodSync(d, 0o755); chmodSync(slot, 0o755); chmodSync(join(slot, 'sub'), 0o755);
  assert.doesNotThrow(() => assertProtectedPath(slot, uid));
  assert.equal(verifySlot(slot, manifest, { expectUid: uid }).files, 2);
  chmodSync(slot, 0o777); rejects(() => assertProtectedPath(slot, uid), 'SLOT_PATH_NOT_PROTECTED');
  chmodSync(slot, 0o1777); rejects(() => assertProtectedPath(slot, uid), 'SLOT_PATH_NOT_PROTECTED'); // sticky does not excuse the slot itself
  chmodSync(slot, 0o755);
  chmodSync(d, 0o777); rejects(() => verifySlot(slot, manifest, { expectUid: uid }), 'SLOT_PATH_NOT_PROTECTED');
  chmodSync(d, 0o1777); assert.doesNotThrow(() => assertProtectedPath(slot, uid));
  chmodSync(d, 0o755);
  if (uid === 0) { chownSync(d, 4242, 4242); rejects(() => assertProtectedPath(slot, 0), 'SLOT_PATH_NOT_PROTECTED'); chownSync(d, 0, 0); }
  // Without expectUid the precondition is not checked (installer path), exactly as before.
  chmodSync(d, 0o777); assert.equal(verifySlot(slot, manifest).files, 2); chmodSync(d, 0o755);
});
