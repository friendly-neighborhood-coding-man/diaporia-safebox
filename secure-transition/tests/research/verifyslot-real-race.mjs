// Real (timing) race against unmodified verifySlot: a separate attacker PROCESS keeps slot/sub = EVIL and briefly swaps a
// genuine twin directory in and out (rename, rename back). Any verifySlot SUCCESS is a bypass: EVIL never matches the
// manifest digest, so success means the walk read the twin while the identity checks still passed. MOCK files only.
// Usage: node real-race.mjs <secure-transition dir> <iterations>
import fs from 'node:fs'; import { join } from 'node:path'; import { tmpdir } from 'node:os'; import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url'; import { spawn } from 'node:child_process';
const [ST, N = '2000'] = process.argv.slice(2);
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const GEN = Buffer.from('genuine\n'), EVIL = Buffer.from('EVIL!!!\n');
const d = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'sstp-real-'))); const slot = join(d, 'slot'); fs.mkdirSync(slot);
const files = []; const sub = join(slot, 'sub'), twin = join(d, 'twin'); fs.mkdirSync(sub); fs.mkdirSync(twin);
for (let i = 0; i < 40; i++) { const n = `f${i}.mjs`; fs.writeFileSync(join(sub, n), EVIL); fs.writeFileSync(join(twin, n), GEN); fs.chmodSync(join(sub, n), 0o644); fs.chmodSync(join(twin, n), 0o644); files.push({ path: 'sub/' + n, sha256: sha(GEN), mode: 0o644 }); }
const manifest = { files };
const atk = spawn(process.execPath, ['-e', `const fs=require('fs');const [s,t,a]=process.argv.slice(1);for(;;){try{fs.renameSync(s,a);fs.renameSync(t,s);for(let i=0;i<200;i++);fs.renameSync(s,t);fs.renameSync(a,s);}catch{}}`, sub, twin, join(d, 'aside')], { stdio: 'ignore' });
const tally = {}; let success = 0;
for (let i = 0; i < Number(N); i++) { try { verifySlot(slot, manifest); success++; } catch (e) { tally[e.code] = (tally[e.code] ?? 0) + 1; } }
atk.kill('SIGKILL');
console.log(JSON.stringify({ tree: ST, iterations: Number(N), verifySlotSuccessWhileSlotHeldEvil: success, refusals: tally }));
