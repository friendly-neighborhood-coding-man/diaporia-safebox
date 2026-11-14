// Remove one verifySlot protection at a time in PR #27 (d6172ec) and run the SSTP unit suite + the race probes.
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
const ST = process.argv[2]; const F = join(ST, 'src/package/install.mjs'); const PROBE = process.argv[3];
const M = [
  ['readCheckedFile: O_NOFOLLOW removed', 'openSync(p, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK)', 'openSync(p, C.O_RDONLY | C.O_NONBLOCK)'],
  ['readCheckedFile: O_NONBLOCK removed', 'openSync(p, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK)', 'openSync(p, C.O_RDONLY | C.O_NOFOLLOW)'],
  ['readCheckedFile: dev/ino identity check removed', "if (st.dev !== lst.dev || st.ino !== lst.ino) fail('SLOT_CHANGED_DURING_VERIFY', r);", ''],
  ['readCheckedFile: read by path again (readFileSync(p))', 'return { mode: st.mode & 0o7777, data: readFileSync(fd) };', 'return { mode: st.mode & 0o7777, data: readFileSync(p) };'],
  ['file stillSame after read removed', 'found.set(r, readCheckedFile(p, r, st, { expectUid })); stillSame(p, r, st);', 'found.set(r, readCheckedFile(p, r, st, { expectUid }));'],
  ['directory pinDir removed', 'if (st.isDirectory()) { pinDir(p, r, st); walk(p, r); stillSame(p, r, st); }', 'if (st.isDirectory()) { walk(p, r); stillSame(p, r, st); }'],
  ['directory stillSame after walk removed', 'if (st.isDirectory()) { pinDir(p, r, st); walk(p, r); stillSame(p, r, st); }', 'if (st.isDirectory()) { pinDir(p, r, st); walk(p, r); }'],
  ['stillSame realpath check removed', "if (rp !== p) fail('SLOT_CONTAINS_SYMLINK', rel);", ''],
  ['top-level stillSame(slotDir) removed', "walk(slotDir, ''); stillSame(slotDir, '.', top);", "walk(slotDir, '');"],
];
const orig = readFileSync(F, 'utf8'); const rows = [];
for (const [name, from, to] of M) {
  if (!orig.includes(from)) { rows.push({ name, error: 'PATTERN_NOT_FOUND' }); continue; }
  writeFileSync(F, orig.replace(from, to));
  try {
    const u = spawnSync(process.execPath, ['--test', ...['authority', 'install-journal', 'tar-manifest', 'tuf'].map(x => `tests/unit/${x}.spec.mjs`)], { cwd: ST, encoding: 'utf8', timeout: 600000 });
    const fail = Number(/# fail (\d+)/.exec(u.stdout)?.[1] ?? -1);
    const pr = spawnSync(process.execPath, [PROBE, ST], { encoding: 'utf8' }); let probe = null;
    try { probe = JSON.parse(pr.stdout).results.map(r => `${r.name.slice(0, 3)}:${r.verifySlot}${r.invariantHeld ? '' : '(INVARIANT BROKEN)'}`); } catch { probe = 'probe error ' + pr.stderr.slice(0, 200); }
    rows.push({ name, unitFailures: fail, caughtByUnitTests: fail > 0, failingTests: [...u.stdout.matchAll(/^not ok \d+ - (.*)$/gm)].map(m => m[1]).slice(0, 3), probe });
  } finally { writeFileSync(F, orig); }
  console.log(JSON.stringify(rows.at(-1)));
}
writeFileSync(process.argv[4], JSON.stringify(rows, null, 1));
