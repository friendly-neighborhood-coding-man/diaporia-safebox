// Track C mutation checks: V1/V2 legacy hardening (PRs #19, #21, #23, #24 + PR #28 conditions). NOT part of the V6 candidate.
// Each mutant removes ONE protection in place, runs the named test files, restores the file. "Caught" = >=1 test fails.
// Run in a separate git worktree (it edits sources in place):  node scripts/v2/legacy-hardening-mutations.mjs [out.json]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
const M = [
  // PR #19 keygen
  ['#19 keygen private read follows symlinks', 'src/v2/launch/keygen.mjs', "try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }", 'try { fd = openSync(path, C.O_RDONLY | (C.O_NONBLOCK ?? 0)); }', ['tests/v2/keygen-exclusive.test.mjs']],
  ['#19 keygen private mode check removed', 'src/v2/launch/keygen.mjs', "if (mode === 0o600 && (st.mode & 0o077) !== 0) fail('KEY_FILE_TOO_PERMISSIVE', path);", '', ['tests/v2/keygen-exclusive.test.mjs']],
  // PR #21 launcher argv + PR #28 conditions
  ['#21 find via sh -c string', 'src/v2/launch/argv-exec.mjs', "return execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });", "return execFileSync('sh', ['-c', [cmd, ...args].join(' ')], { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });", ['tests/v2/argv-exec.test.mjs']],
  ['#21-cond absolute-path operand check removed', 'src/v2/launch/argv-exec.mjs', "if (!p.startsWith('/')) {", 'if (false) {', ['tests/v2/argv-exec.test.mjs']],
  ['#21-cond find failure no longer recorded', 'src/v2/launch/argv-exec.mjs', "lines.push(`FIND_FAILED ${root} (${e.code ?? e.status ?? 'error'})`);", '', ['tests/v2/argv-exec.test.mjs']],
  // PR #23 V1 key files
  ['#23 V1 owner key read follows symlinks', 'src/v1/authz.mjs', "try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }", 'try { fd = openSync(path, C.O_RDONLY | (C.O_NONBLOCK ?? 0)); }', ['tests/v1/keyfile-nofollow.test.mjs']],
  ['#23 V1 executor key read follows symlinks', 'src/v1/near/executor.mjs', "try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }", 'try { fd = openSync(path, C.O_RDONLY | (C.O_NONBLOCK ?? 0)); }', ['tests/v1/keyfile-nofollow.test.mjs']],
  // PR #24 owner log + PR #28 writer condition
  ['#24 owner log view follows symlinks', 'src/v2/supervisor/owner.mjs', "try { fd = openSync(logPath, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }", 'try { fd = openSync(logPath, C.O_RDONLY | (C.O_NONBLOCK ?? 0)); }', ['tests/v2/owner-log-fd.test.mjs']],
  ['#24-cond owner log writer follows symlinks', 'src/v2/supervisor/owner.mjs', "C.O_WRONLY | C.O_APPEND | C.O_CREAT | (C.O_NOFOLLOW ?? 0) | (C.O_NONBLOCK ?? 0), 0o600", 'C.O_WRONLY | C.O_APPEND | C.O_CREAT | (C.O_NONBLOCK ?? 0), 0o600', ['tests/v2/owner-log-fd.test.mjs']],
  // Independent-review follow-ups (Mission 2): F1 FIFO, F9 replaced log, F13 link-not-rename, F14 torn line
  ['F1 keygen private read blocks on a FIFO', 'src/v2/launch/keygen.mjs', "try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }", 'try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW); }', ['tests/v2/legacy-review-followup.test.mjs']],
  ['F1 owner log view blocks on a FIFO', 'src/v2/supervisor/owner.mjs', "try { fd = openSync(logPath, C.O_RDONLY | C.O_NOFOLLOW | (C.O_NONBLOCK ?? 0)); }", 'try { fd = openSync(logPath, C.O_RDONLY | C.O_NOFOLLOW); }', ['tests/v2/legacy-review-followup.test.mjs']],
  ['F9 owner log view not bound to one file', 'src/v2/supervisor/owner.mjs', "else if (v.fileId !== id) {", 'else if (false) {', ['tests/v2/legacy-review-followup.test.mjs']],
  ['F13 keygen loser renames over the winner', 'src/v2/launch/keygen.mjs', 'try { linkSync(tmp, path); }', 'try { renameSync(tmp, path); }', ['tests/v2/keygen-exclusive.test.mjs', 'tests/v2/legacy-review-followup.test.mjs']],
  ['F14 owner log view consumes a torn last line', 'src/v2/supervisor/owner.mjs', 'const cut = got.lastIndexOf(0x0a) + 1;', 'const cut = got.length;', ['tests/v2/owner-log-fd.test.mjs', 'tests/v2/legacy-review-followup.test.mjs']],
];
const rows = [];
for (const [name, file, from, to, tests] of M) {
  const orig = readFileSync(file, 'utf8');
  if (!orig.includes(from)) { rows.push({ name, file, error: 'PATTERN_NOT_FOUND' }); console.log(JSON.stringify(rows.at(-1))); continue; }
  writeFileSync(file, orig.replace(from, to));
  try {
    const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', ...tests], { encoding: 'utf8', timeout: 600_000 });
    const fail = Number(/# fail (\d+)/.exec(r.stdout)?.[1] ?? -1);
    rows.push({ name, file, tests, caught: fail !== 0, failingTests: fail, examples: [...r.stdout.matchAll(/^not ok \d+ - (.*)$/gm)].map(m => m[1]).slice(0, 3) });
  } finally { writeFileSync(file, orig); }
  console.log(JSON.stringify(rows.at(-1)));
}
const out = process.argv[2] ?? 'docs/evidence/legacy-hardening/legacy-mutations.json';
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ generatedBy: 'scripts/v2/legacy-hardening-mutations.mjs', caught: rows.filter(r => r.caught).length, total: rows.length, patternErrors: rows.filter(r => r.error).length, rows }, null, 2));
console.log(`caught ${rows.filter(r => r.caught).length}/${rows.length}, pattern errors ${rows.filter(r => r.error).length}`);
