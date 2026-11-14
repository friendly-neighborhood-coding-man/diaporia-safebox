// Exhaustive deterministic interposition against verifySlot, implementation-agnostic (runs unchanged against the PR #27
// path-recheck walk and the descriptor-relative walk). node:fs is wrapped and pushed into the ESM named exports with
// module.syncBuiltinESMExports(), so the unmodified install.mjs calls the wrappers. The wrappers count every fs call
// verifySlot makes; the "attacker" performs its renames / writes immediately BEFORE call number k (single-step attacks)
// or before calls i and j (swap-and-swap-back), for EVERY k / every pair i < j of the untouched trace. This models a
// concurrent same-uid attacker that wins the race at that exact point. MOCK files only.
//
// IN_CALL_BYPASS = verifySlot returned SUCCESS although, when it returned, the slot held content that does not match
// the manifest. Every mutation here happens during the call, so any IN_CALL_BYPASS is a verifier defect.
// Mutations AFTER the call returns (verify-then-use) are not modelled: they always succeed against any verifier unless
// the attacker cannot write the slot (see tests/os).
// Usage: node verifyslot-exhaustive.mjs <secure-transition dir> [out.json]
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ST = process.argv[2];
const sha = (b) => createHash('sha256').update(b).digest('hex');
const HOOKED = ['openSync', 'readdirSync', 'lstatSync', 'statSync', 'realpathSync', 'fstatSync', 'readFileSync', 'closeSync'];
const orig = Object.fromEntries(HOOKED.map(k => [k, fs[k]]));
const origNative = fs.realpathSync.native;
let step = 0, plan = null, trace = null, inAct = false;
for (const k of HOOKED) fs[k] = function (...a) {
  if (inAct) return orig[k].apply(this, a);
  step++;
  if (trace) trace.push(k);
  if (plan) for (const p of plan) if (p.at === step && !p.done) { p.done = true; inAct = true; try { p.act(); } finally { inAct = false; } }
  return orig[k].apply(this, a);
};
fs.realpathSync.native = origNative;
syncBuiltinESMExports();
const { verifySlot } = await import(pathToFileURL(join(ST, 'src/package/install.mjs')).href);

const GEN = Buffer.from('export const ok = "genuine";\n'), EVIL = Buffer.from('export const ok = "EVIL!!!";\n');
const files = ['a.mjs', 'sub/x.mjs', 'z.mjs'];
const manifest = { files: files.map(path => ({ path, sha256: sha(GEN), mode: 0o644 })) };
const put = (p, b) => { fs.writeFileSync(p, b); fs.chmodSync(p, 0o644); };

function world(evilA = false, evilSub = false) {
  const d = orig.realpathSync(fs.mkdtempSync(join(tmpdir(), 'sstp-ex-'))); const slot = join(d, 'slot');
  fs.mkdirSync(join(slot, 'sub'), { recursive: true });
  put(join(slot, 'a.mjs'), evilA ? EVIL : GEN); put(join(slot, 'sub/x.mjs'), evilSub ? EVIL : GEN); put(join(slot, 'z.mjs'), GEN);
  fs.mkdirSync(join(d, 'twin')); put(join(d, 'twin/x.mjs'), GEN);      // genuine twin of sub/
  fs.mkdirSync(join(d, 'evildir')); put(join(d, 'evildir/x.mjs'), EVIL); // EVIL replacement for sub/
  put(join(d, 'gen-a'), GEN); put(join(d, 'evil-a'), EVIL);
  return { d, slot };
}
// The slot matches the manifest at return: exactly these entries, no symlinks, genuine bytes.
const listAll = (dir, rel = '') => fs.readdirSync(dir).flatMap(n => { const p = join(dir, n), r = rel ? `${rel}/${n}` : n; const s = fs.lstatSync(p); return s.isDirectory() && !s.isSymbolicLink() ? [r + '/', ...listAll(p, r)] : [r]; });
const allGenuine = (slot) => { try { if (listAll(slot).sort().join(',') !== 'a.mjs,sub/,sub/x.mjs,z.mjs') return false; } catch { return false; }
  return files.every(f => { try { const s = fs.lstatSync(join(slot, f)); return !s.isSymbolicLink() && fs.readFileSync(join(slot, f)).equals(GEN); } catch { return false; } }); };

// Attacks. setup(world) -> {evilA, evilSub}; steps: list of actions, each placed before one fs call.
const R = (a, b) => fs.renameSync(a, b);
const ATTACKS = {
  'A1 a.mjs replaced by an EVIL file (persistent)': { init: [false, false], acts: (w) => [() => R(join(w.d, 'evil-a'), join(w.slot, 'a.mjs'))] },
  'A2 sub/ replaced by an EVIL directory (persistent)': { init: [false, false], acts: (w) => [() => { R(join(w.slot, 'sub'), join(w.d, 'gone')); R(join(w.d, 'evildir'), join(w.slot, 'sub')); }] },
  'A3 a.mjs rewritten in place, same inode and length (persistent)': { init: [false, false], acts: (w) => [() => { const fd = fs.openSync(join(w.slot, 'a.mjs'), 'r+'); fs.writeSync(fd, EVIL, 0, EVIL.length, 0); fs.closeSync(fd); }] },
  'A4 extra file created inside sub/ (persistent)': { init: [false, false], acts: (w) => [() => { const p = join(w.slot, 'sub/extra.mjs'); fs.writeFileSync(p, GEN); fs.chmodSync(p, 0o644); }] },
  'A5 a.mjs replaced by a symlink to a genuine file (persistent)': { init: [false, false], acts: (w) => [() => { R(join(w.slot, 'a.mjs'), join(w.d, 'aside-a')); fs.symlinkSync(join(w.d, 'gen-a'), join(w.slot, 'a.mjs')); }] },
  'P1 sub/ swap-and-swap-back with a REAL genuine twin (slot holds EVIL sub/)': { init: [false, true], acts: (w) => [
    () => { R(join(w.slot, 'sub'), join(w.d, 'aside')); R(join(w.d, 'twin'), join(w.slot, 'sub')); },
    () => { R(join(w.slot, 'sub'), join(w.d, 'twin')); R(join(w.d, 'aside'), join(w.slot, 'sub')); }] },
  'P2 sub/ swap-and-swap-back with a SYMLINK to the genuine twin': { init: [false, true], acts: (w) => [
    () => { R(join(w.slot, 'sub'), join(w.d, 'aside')); fs.symlinkSync(join(w.d, 'twin'), join(w.slot, 'sub')); },
    () => { fs.unlinkSync(join(w.slot, 'sub')); R(join(w.d, 'aside'), join(w.slot, 'sub')); }] },
  'P3 a.mjs swap-and-swap-back with a genuine file (slot holds EVIL a.mjs)': { init: [true, false], acts: (w) => [
    () => { R(join(w.slot, 'a.mjs'), join(w.d, 'aside-a')); R(join(w.d, 'gen-a'), join(w.slot, 'a.mjs')); },
    () => { R(join(w.slot, 'a.mjs'), join(w.d, 'gen-a')); R(join(w.d, 'aside-a'), join(w.slot, 'a.mjs')); }] },
};

function runOnce(init, schedule) {
  const w = world(...init); const acts = ATTACKS[schedule.name].acts(w);
  plan = schedule.at.map((at, i) => ({ at, act: () => { try { acts[i](); } catch (e) { schedule.actError = e.code; } }, done: false }));
  step = 0; let out;
  try { verifySlot(w.slot, manifest); out = 'SUCCESS'; } catch (e) { out = e.code ?? String(e.message).slice(0, 40); }
  const fired = plan.filter(p => p.done).length; plan = null;
  const genuine = allGenuine(w.slot); fs.rmSync(w.d, { recursive: true, force: true });
  return { out, fired, genuine };
}

// Baseline trace of the untouched slot (genuine) to know how many fs calls verifySlot makes.
let baseTrace;
{ const w = world(); trace = []; step = 0; verifySlot(w.slot, manifest); baseTrace = trace; trace = null; fs.rmSync(w.d, { recursive: true, force: true }); }
const N = baseTrace.length;
// Boundary used to classify bypasses: the last call that reads file content (readFileSync). Mutations up to it happen
// during the walk itself (what PR #27 tried to close); later ones fall in the closing re-check window.
const lastRead = baseTrace.lastIndexOf('readFileSync') + 1;
const summary = {}; const bypasses = [];
for (const [name, a] of Object.entries(ATTACKS)) {
  const pairs = a.acts({ d: '', slot: '' }).length === 2;
  const sched = []; if (pairs) { for (let i = 1; i <= N; i++) for (let j = i + 1; j <= N + 1; j++) sched.push([i, j]); } else for (let k = 1; k <= N; k++) sched.push([k]);
  const s = { schedules: 0, fullyFired: 0, success: 0, inCallBypass: 0, bypassDuringWalk: 0, bypassInClosingWindow: 0, refusals: {} };
  for (const at of sched) {
    const r = runOnce(a.init, { name, at });
    s.schedules++; if (r.fired === at.length) s.fullyFired++;
    if (r.out === 'SUCCESS') { s.success++; if (!r.genuine) { s.inCallBypass++; if (Math.max(...at) <= lastRead) s.bypassDuringWalk++; else s.bypassInClosingWindow++; s.bypassAt = s.bypassAt ?? []; s.bypassAt.push(at.join('+') + ':' + at.map(k => baseTrace[k - 1] ?? 'end').join('+')); if (bypasses.length < 40) bypasses.push({ attack: name, at, before: at.map(k => baseTrace[k - 1] ?? 'end') }); } }
    else s.refusals[r.out] = (s.refusals[r.out] ?? 0) + 1;
  }
  summary[name] = s;
}
const ctl = (() => { const w = world(); let o; try { verifySlot(w.slot, manifest); o = 'SUCCESS'; } catch (e) { o = e.code; } fs.rmSync(w.d, { recursive: true, force: true }); return o; })();
const result = { tree: ST, node: process.version, uid: process.getuid?.(), fsCallsPerVerify: N, lastContentReadCall: lastRead, closingWindowCalls: baseTrace.slice(lastRead), control: ctl, summary, totalInCallBypass: Object.values(summary).reduce((a, s) => a + s.inCallBypass, 0), totalBypassDuringWalk: Object.values(summary).reduce((a, s) => a + s.bypassDuringWalk, 0), sampleBypasses: bypasses };
console.log(JSON.stringify(result, null, 1));
if (process.argv[3]) fs.writeFileSync(process.argv[3], JSON.stringify(result, null, 1) + '\n');
