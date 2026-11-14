// Independent race probes for SSTP verifySlot at a given tree (PR #27 d6172ec vs c256ffa). verifySlot itself is NOT
// replaced: node:fs functions are wrapped and pushed into ESM named exports with module.syncBuiltinESMExports(), so the
// unmodified install.mjs calls the wrappers. Each wrapper performs the attacker's rename/symlink at one exact point,
// i.e. it models a concurrent same-user attacker that WINS the race at that point (deterministic interposition, not a
// race won by timing). MOCK files only.
// Usage: node races.mjs <secure-transition dir>
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
const ST = process.argv[2];
const sha = (b) => createHash('sha256').update(b).digest('hex');
const orig = { readdirSync: fs.readdirSync, realpathSync: fs.realpathSync, openSync: fs.openSync, lstatSync: fs.lstatSync };
let hooks = {};
for (const k of Object.keys(orig)) fs[k] = function (...a) { const h = hooks[k]; if (h) h(String(a[0]), a); return orig[k].apply(this, a); };
fs.realpathSync.native = orig.realpathSync.native;
syncBuiltinESMExports();
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);
const GEN = Buffer.from('export const ok = "genuine";\n'), EVIL = Buffer.from('export const ok = "EVIL";\n');
const manifest = { files: [{ path: 'a.mjs', sha256: sha(GEN), mode: 0o644 }, { path: 'sub/x.mjs', sha256: sha(GEN), mode: 0o644 }, { path: 'z.mjs', sha256: sha(GEN), mode: 0o644 }] };
function world() {
  const d = orig.realpathSync(fs.mkdtempSync(join(tmpdir(), 'sstp-race-'))); const slot = join(d, 'slot');
  for (const p of [slot, join(slot, 'sub')]) fs.mkdirSync(p);
  for (const f of ['a.mjs', 'sub/x.mjs', 'z.mjs']) { fs.writeFileSync(join(slot, f), GEN); fs.chmodSync(join(slot, f), 0o644); }
  return { d, slot };
}
const contentAtReturn = (slot) => Object.fromEntries(['a.mjs', 'sub/x.mjs', 'z.mjs'].map(f => { const p = join(slot, f); let s; try { s = fs.lstatSync(p); } catch { return [f, 'MISSING']; } return [f, (s.isSymbolicLink() ? 'SYMLINK:' : '') + (fs.readFileSync(p).equals(GEN) ? 'genuine' : 'EVIL')]; }));
const results = [];
async function run(name, setup) {
  const { d, slot } = world(); hooks = {}; let fired = []; setup({ d, slot, fire: (x) => fired.push(x) });
  let out; try { out = { ok: true, r: verifySlot(slot, manifest) }; } catch (e) { out = { ok: false, code: e.code, detail: e.detail ?? e.message }; }
  hooks = {};
  const row = { name, verifySlot: out.ok ? 'SUCCESS' : out.code, fired, slotAtReturn: contentAtReturn(slot) };
  row.invariantHeld = !out.ok || Object.values(row.slotAtReturn).every(v => v === 'genuine');
  results.push(row); fs.rmSync(d, { recursive: true, force: true });
}
// S0 control
await run('S0 control: untouched slot', () => {});
// S1 file swapped for a symlink to identical bytes AFTER open/read (before the post-read stillSame check)
await run('S1 file -> symlink(identical bytes) after open, before stillSame', ({ d, slot, fire }) => {
  let n = 0; hooks.realpathSync = (p) => { if (p === join(slot, 'a.mjs') && !n++) { const c = join(d, 'copy'); fs.writeFileSync(c, GEN); fs.chmodSync(c, 0o644); fs.renameSync(p, join(d, 'aside')); fs.symlinkSync(c, p); fire('swapped a.mjs->symlink'); } };
});
// S2 file replaced by another regular file (EVIL) after open, before stillSame
await run('S2 file -> other regular file (EVIL) after open, before stillSame', ({ d, slot, fire }) => {
  let n = 0; hooks.realpathSync = (p) => { if (p === join(slot, 'a.mjs') && !n++) { const e = join(d, 'evil'); fs.writeFileSync(e, EVIL); fs.chmodSync(e, 0o644); fs.renameSync(p, join(d, 'aside')); fs.renameSync(e, p); fire('replaced a.mjs'); } };
});
// S3 file replaced AFTER its own checks completed, while a later entry is verified (verify-then-use)
await run('S3 a.mjs replaced (EVIL) after its checks, while z.mjs is verified', ({ d, slot, fire }) => {
  let n = 0; hooks.openSync = (p) => { if (p === join(slot, 'z.mjs') && !n++) { const e = join(d, 'evil'); fs.writeFileSync(e, EVIL); fs.chmodSync(e, 0o644); fs.renameSync(e, join(slot, 'a.mjs')); fire('replaced a.mjs late'); } };
});
// S4 directory swap-and-swap-back: slot/sub really holds EVIL; a genuine twin directory is renamed in for the walk of sub,
// then the EVIL directory is renamed back before sub's final identity check.
await run('S4 dir swap-and-swap-back with a REAL twin directory around the recursion into sub/', ({ d, slot, fire }) => {
  fs.writeFileSync(join(slot, 'sub', 'x.mjs'), EVIL); fs.chmodSync(join(slot, 'sub', 'x.mjs'), 0o644);
  const twin = join(d, 'twin'); fs.mkdirSync(twin); fs.writeFileSync(join(twin, 'x.mjs'), GEN); fs.chmodSync(join(twin, 'x.mjs'), 0o644);
  const sub = join(slot, 'sub'), aside = join(d, 'evil-sub'); let phase = 0;
  hooks.readdirSync = (p) => { if (p === sub && phase === 0) { phase = 1; fs.renameSync(sub, aside); fs.renameSync(twin, sub); fire('twin in (after pinDir, before readdir)'); } };
  hooks.realpathSync = (p) => { if (p === sub && phase === 1) { phase = 2; fs.renameSync(sub, twin); fs.renameSync(aside, sub); fire('evil back (before stillSame(sub))'); } };
});
// S5 directory -> symlink swap-and-swap-back (symlink in for the walk, original back before the final check)
await run('S5 dir swap-and-swap-back with a SYMLINK to a twin around the recursion into sub/', ({ d, slot, fire }) => {
  fs.writeFileSync(join(slot, 'sub', 'x.mjs'), EVIL); fs.chmodSync(join(slot, 'sub', 'x.mjs'), 0o644);
  const twin = join(d, 'twin'); fs.mkdirSync(twin); fs.writeFileSync(join(twin, 'x.mjs'), GEN); fs.chmodSync(join(twin, 'x.mjs'), 0o644);
  const sub = join(slot, 'sub'), aside = join(d, 'evil-sub'); let phase = 0;
  hooks.readdirSync = (p) => { if (p === sub && phase === 0) { phase = 1; fs.renameSync(sub, aside); fs.symlinkSync(twin, sub); fire('symlink in'); } };
  hooks.realpathSync = (p) => { if (p === sub && phase === 1) { phase = 2; fs.unlinkSync(sub); fs.renameSync(aside, sub); fire('evil back'); } };
});
// S6 directory replaced (EVIL twin kept) after its final check while a later entry is verified
await run('S6 sub/ replaced by an EVIL directory after its checks, while z.mjs is verified', ({ d, slot, fire }) => {
  const e = join(d, 'evil-dir'); fs.mkdirSync(e); fs.writeFileSync(join(e, 'x.mjs'), EVIL); fs.chmodSync(join(e, 'x.mjs'), 0o644);
  let n = 0; hooks.openSync = (p) => { if (p === join(slot, 'z.mjs') && !n++) { fs.renameSync(join(slot, 'sub'), join(d, 'aside')); fs.renameSync(e, join(slot, 'sub')); fire('sub replaced late'); } };
});
console.log(JSON.stringify({ tree: ST, results }, null, 1));
