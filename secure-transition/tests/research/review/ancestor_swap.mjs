// Deterministic: verifySlot verifies a genuine slot reached through an ancestor that the attacker swapped in BEFORE the
// call; the attacker swaps the ancestor back AFTER the final-pass slot-path check (realpath + lstat) but BEFORE the
// final directory checks. The held descriptors still point at the genuine twin, so nothing in the final pass changes.
import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; import { join } from 'node:path';
import { createHash } from 'node:crypto'; import { pathToFileURL } from 'node:url';
const ST = process.argv[2]; const sha = (b) => createHash('sha256').update(b).digest('hex');
const GEN = Buffer.from('genuine\n'), EVIL = Buffer.from('EVIL!!!\n');
const base = fs.realpathSync(fs.mkdtempSync('/tmp/rv-anc-')); const P = join(base, 'parent'), slot = join(P, 'slot');
const mk = (dir, a) => { fs.mkdirSync(join(dir, 'slot/sub'), { recursive: true }); for (const [f, b] of [['a.mjs', a], ['sub/x.mjs', GEN]]) { fs.writeFileSync(join(dir, 'slot', f), b); fs.chmodSync(join(dir, 'slot', f), 0o644); } };
mk(P, EVIL); mk(join(base, 'twin'), GEN);
const manifest = { files: ['a.mjs', 'sub/x.mjs'].map(path => ({ path, sha256: sha(GEN), mode: 0o644 })) };
fs.renameSync(P, join(base, 'aside')); fs.renameSync(join(base, 'twin'), P);          // swap in before the call
const oL = fs.lstatSync; let slotLstats = 0, fired = false;
fs.lstatSync = function (p, ...r) { const out = oL.call(this, p, ...r);
  if (p === slot && ++slotLstats === 2 && !fired) { fired = true; fs.renameSync(P, join(base, 'twin')); fs.renameSync(join(base, 'aside'), P); } // swap back
  return out; };
syncBuiltinESMExports();
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);
let o; try { o = verifySlot(slot, manifest); } catch (e) { o = e.code; }
console.log(JSON.stringify({ tree: ST, fired, verifySlot: o, aMjsAtReturn: fs.readFileSync(join(slot, 'a.mjs'), 'utf8').trim() }));
fs.rmSync(base, { recursive: true, force: true });
