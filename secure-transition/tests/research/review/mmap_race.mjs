import fs from 'node:fs'; import { spawn } from 'node:child_process'; import { join } from 'node:path'; import { createHash } from 'node:crypto'; import { pathToFileURL } from 'node:url';
const [ST, N = '3000'] = process.argv.slice(2);
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);
const sha = (b) => createHash('sha256').update(b).digest('hex'); const GEN = Buffer.from('export const ok = "genuine";\n');
const d = fs.realpathSync(fs.mkdtempSync('/tmp/rv-mrace-')); const slot = join(d, 'slot'); fs.mkdirSync(join(slot, 'sub'), { recursive: true });
for (const f of ['a.mjs', 'sub/x.mjs', 'z.mjs']) { fs.writeFileSync(join(slot, f), GEN); fs.chmodSync(join(slot, f), 0o644); }
const manifest = { files: ['a.mjs', 'sub/x.mjs', 'z.mjs'].map(path => ({ path, sha256: sha(GEN), mode: 0o644 })) };
const stop = join(d, 'stop'); const h = spawn('python3', [new URL('./mmap_flip.py', import.meta.url).pathname, join(slot, 'a.mjs'), stop], { stdio: 'inherit' });
while (!fs.existsSync(stop + '.ready')) await new Promise(r => setTimeout(r, 5));
const c0 = fs.statSync(join(slot, 'a.mjs'), { bigint: true }).ctimeNs; const tally = {}; let evilAtReturn = 0;
for (let i = 0; i < Number(N); i++) { let o; try { verifySlot(slot, manifest); o = 'SUCCESS'; if (!fs.readFileSync(join(slot, 'a.mjs')).equals(GEN)) evilAtReturn++; } catch (e) { o = e.code; } tally[o] = (tally[o] ?? 0) + 1; }
fs.writeFileSync(stop, ''); await new Promise(r => h.on('exit', r));
console.log(JSON.stringify({ tree: ST, iterations: Number(N), outcomes: tally, successThenForeignOnImmediateReread: evilAtReturn, ctimeUnchangedWholeRun: c0 === fs.statSync(join(slot, 'a.mjs'), { bigint: true }).ctimeNs }));
fs.rmSync(d, { recursive: true, force: true });
