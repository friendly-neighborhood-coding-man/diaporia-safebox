// Mutation check for the descriptor-relative verifySlot: remove or weaken one protection at a time in
// src/package/install.mjs, run the SSTP unit suite (tests/unit) and, as root, the OS suite (tests/os), restore.
// A mutant counts as caught only on a parsed "# fail N" with N > 0 (a hang or crash is reported separately).
// Edits the file in place and restores it; run in a disposable worktree.
// Usage: node verifyslot-fd-mutants.mjs <secure-transition dir> <out.json>
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
const [ST, OUT] = process.argv.slice(2); const F = join(ST, 'src/package/install.mjs');
const M = [
  ['walk descends by slot PATH instead of the parent descriptor (PR #27 style)', 'const r = rel ? `${rel}/${n}` : n; const p = at(dfd, n);', 'const r = rel ? `${rel}/${n}` : n; const p = join(slotDir, r);'],
  ['walk lists directories by PATH instead of the descriptor', "const names = readdirSync(`${FD_DIR}/${dfd}`).sort();\n    dirs.push", "const names = readdirSync(rel ? join(slotDir, rel) : slotDir).sort();\n    dirs.push"],
  ['child lstat follows symlinks (stat)', 'let st; try { st = lstatSync(p, { bigint: true }); }', 'let st; try { st = statSync(p, { bigint: true }); }'],
  ['openDir: O_NOFOLLOW removed', 'fd = openSync(p, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);', 'fd = openSync(p, C.O_RDONLY | C.O_DIRECTORY);'],
  ['openDir: identity check removed', "if (!sameObj(st, lst) || !st.isDirectory()) fail('SLOT_CHANGED_DURING_VERIFY', r || '.');", ''],
  ['readAt: O_NOFOLLOW removed', 'fd = openSync(p, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK);', 'fd = openSync(p, C.O_RDONLY | C.O_NONBLOCK);'],
  ['readAt: identity check removed', "if (!sameObj(st, lst)) fail('SLOT_CHANGED_DURING_VERIFY', r);", ''],
  ['readAt: post-read ctime/size check removed', "if (post.size !== st.size || post.ctimeNs !== st.ctimeNs || BigInt(data.length) !== st.size) fail('SLOT_CHANGED_DURING_VERIFY', r);", ''],
  ['final pass: entry re-check loop removed', "if (!sameObj(now, e.st) || now.isSymbolicLink() || now.ctimeNs !== e.st.ctimeNs || (!e.dir && now.size !== e.st.size)) fail('SLOT_CHANGED_DURING_VERIFY', e.r);", ''],
  ['final pass: entry ctime comparison removed', 'now.isSymbolicLink() || now.ctimeNs !== e.st.ctimeNs ||', 'now.isSymbolicLink() ||'],
  ['final pass: directory mtime/ctime check removed', "if (now.mtimeNs !== d.st.mtimeNs || now.ctimeNs !== d.st.ctimeNs) fail('SLOT_CHANGED_DURING_VERIFY', d.rel || '.');", ''],
  ['final pass: directory name-set check removed', "if (readdirSync(`${FD_DIR}/${d.dfd}`).sort().join('/') !== d.names.join('/')) fail('SLOT_CHANGED_DURING_VERIFY', d.rel || '.');", ''],
  ['final pass: directories checked root-first (not deepest-first, root last)', 'for (const d of [...dirs].reverse()) {', 'for (const d of dirs) {'],
  ['final pass: slot path identity re-check removed', "if (!sameObj(nowTop, top) || nowTop.isSymbolicLink()) fail('SLOT_CHANGED_DURING_VERIFY', '.');", ''],
  ['protected path: not checked when expectUid is given', 'if (expectUid !== undefined) assertProtectedPath(slotDir, expectUid);', ''],
  ['protected path: sticky bit excuses the slot itself', "if ((st.mode & 0o022) && (cur === slotDir || !sticky))", 'if ((st.mode & 0o022) && !sticky)'],
  ['protected path: ancestors not walked (slot only)', 'const up = dirname(cur); if (up === cur) break; cur = up;', 'break;'],
  ['protected path: any owner accepted', 'if (!okOwner(st)) fail(', 'if (false) fail('],
];
const run = (dir) => {
  const files = readdirSync(join(ST, dir)).filter(f => f.endsWith('.spec.mjs')).map(f => `${dir}/${f}`);
  const u = spawnSync(process.execPath, ['--test', '--test-concurrency=1', ...files], { cwd: ST, encoding: 'utf8', timeout: 600_000 });
  const m = /# fail (\d+)/.exec(u.stdout ?? '');
  return { fail: m ? Number(m[1]) : null, timedOut: u.error?.code === 'ETIMEDOUT', failing: [...(u.stdout ?? '').matchAll(/^not ok \d+ - (.*)$/gm)].map(x => x[1]).slice(0, 3) };
};
const orig = readFileSync(F, 'utf8'); const rows = [];
for (const [name, from, to] of M) {
  if (!orig.includes(from)) { rows.push({ name, error: 'PATTERN_NOT_FOUND' }); console.log(JSON.stringify(rows.at(-1))); continue; }
  writeFileSync(F, orig.replace(from, to));
  try {
    const unit = run('tests/unit'); const os = process.getuid?.() === 0 ? run('tests/os') : { fail: null, note: 'NOT_RUN (not root)' };
    rows.push({ name, unit, os, caught: (unit.fail ?? 0) > 0 || (os.fail ?? 0) > 0 });
  } finally { writeFileSync(F, orig); }
  console.log(JSON.stringify(rows.at(-1)));
}
const caught = rows.filter(r => r.caught).length;
writeFileSync(OUT, JSON.stringify({ tree: ST, caught, total: rows.length, patternErrors: rows.filter(r => r.error).length, rows }, null, 1) + '\n');
console.log(`caught ${caught}/${rows.length}`);
