// Real (timing) race v2 against unmodified verifySlot. Same world as verifyslot-real-race.mjs (slot/sub holds EVIL; a
// genuine twin directory is swapped in and out by rename), but the attacker is a Worker THREAD that publishes a
// counter of completed renames in shared memory. Each cycle is 4 renames: after rename 2 the genuine twin sits at
// slot/sub, after rename 4 the EVIL directory is back. For every verifySlot SUCCESS the script records how many
// renames happened during the call and where the cycle stood when the call returned, so a success is classified as:
//   STABLE_GENUINE   no rename during the call (the slot held the genuine twin for the whole call; not a bypass)
//   GENUINE_AT_RETURN renames during the call, twin in place at return
//   FOREIGN_AT_RETURN renames during the call and the EVIL directory (or a half-swapped state) was in place at return
// MOCK files only. Usage: node verifyslot-real-race-v2.mjs <secure-transition dir> <iterations>
import fs from 'node:fs'; import { join } from 'node:path'; import { tmpdir } from 'node:os'; import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url'; import { Worker } from 'node:worker_threads';
const [ST, N = '3000'] = process.argv.slice(2);
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const GEN = Buffer.from('genuine\n'), EVIL = Buffer.from('EVIL!!!\n');
const d = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'sstp-real2-'))); const slot = join(d, 'slot'); fs.mkdirSync(slot);
const files = []; const sub = join(slot, 'sub'), twin = join(d, 'twin'); fs.mkdirSync(sub); fs.mkdirSync(twin);
for (let i = 0; i < 40; i++) { const n = `f${i}.mjs`; fs.writeFileSync(join(sub, n), EVIL); fs.writeFileSync(join(twin, n), GEN); fs.chmodSync(join(sub, n), 0o644); fs.chmodSync(join(twin, n), 0o644); files.push({ path: 'sub/' + n, sha256: sha(GEN), mode: 0o644 }); }
const manifest = { files };
const sab = new SharedArrayBuffer(16); const ctr = new Int32Array(sab);
const w = new Worker(`const { workerData: { s, t, a, sab } } = require('worker_threads'); const fs = require('fs'); const c = new Int32Array(sab);
  const R = (x, y) => { fs.renameSync(x, y); Atomics.add(c, 0, 1); };
  while (Atomics.load(c, 1) === 0) { try { R(s, a); R(t, s); for (let i = 0; i < 200; i++); R(s, t); R(a, s); } catch { Atomics.add(c, 2, 1); } }`,
  { eval: true, workerData: { s: sub, t: twin, a: join(d, 'aside'), sab } });
await new Promise(r => setTimeout(r, 50));
const tally = {}; const succ = { STABLE_GENUINE: 0, GENUINE_AT_RETURN: 0, FOREIGN_AT_RETURN: 0 };
for (let i = 0; i < Number(N); i++) {
  const before = Atomics.load(ctr, 0);
  let ok = false; try { verifySlot(slot, manifest); ok = true; } catch (e) { tally[e.code] = (tally[e.code] ?? 0) + 1; }
  const after = Atomics.load(ctr, 0);
  if (ok) { if (after === before) succ.STABLE_GENUINE++; else if (after % 4 === 2) succ.GENUINE_AT_RETURN++; else succ.FOREIGN_AT_RETURN++; }
}
Atomics.store(ctr, 1, 1); await w.terminate();
const res = { tree: ST, iterations: Number(N), renames: Atomics.load(ctr, 0), attackerErrors: Atomics.load(ctr, 2), successes: succ, refusals: tally };
console.log(JSON.stringify(res)); fs.rmSync(d, { recursive: true, force: true });
