// Mutation checks for the V6 final candidate (PR #28 findings on #20, #22, #25 reconciled onto the PR #26 freeze).
// V1/V2 legacy hardening (#19, #21, #23, #24) lives on security-research/v1v2-legacy-hardening with its own mutants.
// Each mutant removes ONE protection in place, runs the named test files, restores the file. "Caught" = >=1 test fails.
// Run in a separate git worktree (it edits sources in place):  node scripts/v6/reconcile-mutations.mjs [out.json]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
const ROOTT = ['tests/v3/prototype-action.test.mjs', 'tests/v5/prototype-action.test.mjs', 'tests/v2/prototype-technique.test.mjs'];
const M = [
  // PR #20 Root dispatch, one version at a time
  ['#20 V3 Root lookup reverted to HANDLERS[a.type]', 'src/v3/root/chain.mjs', "const H = typeof a.type === 'string' && Object.hasOwn(HANDLERS, a.type) ? HANDLERS[a.type] : undefined;", 'const H = HANDLERS[a.type];', ROOTT],
  ['#20 V4 Root lookup reverted (HANDLERS4 / H3 passthrough)', 'src/v4/root/chain.mjs', 'const Hd = own4 ?? own3;', 'const Hd = HANDLERS4[a.type] ?? (V3_PASSTHROUGH.has(a.type) ? H3[a.type] : null);', ROOTT],
  ['#20 V4 own-property check on HANDLERS4 removed', 'src/v4/root/chain.mjs', "const own4 = typeof a.type === 'string' && Object.hasOwn(HANDLERS4, a.type) ? HANDLERS4[a.type] : null;", 'const own4 = HANDLERS4[a.type] ?? null;', ROOTT],
  ['#20 V5 Root lookup reverted to truthiness', 'src/v5/root/chain.mjs', "if (typeof a?.type === 'string' && Object.hasOwn(HANDLERS5, a.type)) {", 'if (HANDLERS5[a?.type]) {', ROOTT],
  ['#20 V2 attack technique lookup reverted', 'src/v2/general/zone.mjs', "const fn = typeof msg.technique === 'string' && Object.hasOwn(ATTACKS, msg.technique) ? ATTACKS[msg.technique] : undefined;", 'const fn = ATTACKS[msg.technique];', ROOTT],
  // PR #22 reconciled into the PR #26 loader
  ['#26/#22 Gmail loader follows symlinks', 'src/v6/notify/gmail.mjs', "fd = openSync(path, FS.O_RDONLY | (FS.O_NOFOLLOW ?? 0) | (FS.O_NONBLOCK ?? 0));", 'fd = openSync(path, FS.O_RDONLY | (FS.O_NONBLOCK ?? 0));', ['tests/v6/gmail-cred-file.test.mjs', 'tests/v6/codeql-fixes.test.mjs']],
  ['#26 Gmail loader O_NONBLOCK removed (FIFO)', 'src/v6/notify/gmail.mjs', "fd = openSync(path, FS.O_RDONLY | (FS.O_NOFOLLOW ?? 0) | (FS.O_NONBLOCK ?? 0));", 'fd = openSync(path, FS.O_RDONLY | (FS.O_NOFOLLOW ?? 0));', ['tests/v6/gmail-cred-file.test.mjs']],
  ['#22 Gmail loader mode check removed', 'src/v6/notify/gmail.mjs', "if (POSIX && (st.mode & 0o077) !== 0) throw credError('GMAIL_CREDENTIALS_TOO_PERMISSIVE', 'credentials file must be mode 0600');", '', ['tests/v6/gmail-cred-file.test.mjs']],
  ['#22 Gmail writer O_EXCL removed', 'src/v6/notify/gmail.mjs', "FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW ?? 0), 0o600", 'FS.O_WRONLY | FS.O_CREAT | FS.O_TRUNC, 0o600', ['tests/v6/gmail-cred-file.test.mjs']],
  ['#28-cond Gmail writer field validation removed', 'src/v6/notify/gmail.mjs', "if (typeof v !== 'string' || !v || v.length > 4096 || /[\\u0000-\\u001f\\u007f]/.test(v))", 'if (false)', ['tests/v6/gmail-cred-file.test.mjs']],
  // PR #25 superseded by PR #26 termSafe
  ['#26 termSafe bypassed in the showcase console line', 'scripts/v6/showcase.mjs', '${kind.padEnd(7)} ${termSafe(text)}`', '${kind.padEnd(7)} ${text}`', ['tests/v6/showcase-log-reconcile.test.mjs']],
  ['#26 termSafe U+2028/2029 range removed', 'src/v6/common/term.mjs', '\\u2028-\\u202e', '\\u202a-\\u202e', ['tests/v6/showcase-log-reconcile.test.mjs']],
  ['#25-cond viewer kind unescaped', 'scripts/v6/showcase.mjs', `'<span class="k">'+H(e.kind)+'</span>'`, `'<span class="k">'+e.kind+'</span>'`, ['tests/v6/showcase-log-reconcile.test.mjs']],
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
const out = process.argv[2] ?? 'docs/evidence/v6-final-reconcile/reconcile-mutations.json';
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ generatedBy: 'scripts/v6/reconcile-mutations.mjs', caught: rows.filter(r => r.caught).length, total: rows.length, patternErrors: rows.filter(r => r.error).length, rows }, null, 2));
console.log(`caught ${rows.filter(r => r.caught).length}/${rows.length}, pattern errors ${rows.filter(r => r.error).length}`);
