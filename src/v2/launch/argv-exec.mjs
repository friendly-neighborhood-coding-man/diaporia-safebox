// Argument-vector execution for the root launchers. Paths are never interpolated into a shell string.
import { execFileSync, spawnSync } from 'node:child_process';

function assertArg(a) {
  if (typeof a !== 'string' || a.includes('\0')) {
    const e = new Error('BAD_ARGV');
    e.code = 'BAD_ARGV';
    throw e;
  }
}

/** Path operands for find/stat must be absolute: GNU find treats a leading '-' operand as an expression even after
 *  '--' (PR #28 condition on #21), so a relative or dash-led path is refused instead of being interpreted. */
export function assertAbsolutePath(p) {
  assertArg(p);
  if (!p.startsWith('/')) { const e = new Error('PATH_NOT_ABSOLUTE: ' + JSON.stringify(p).slice(0, 80)); e.code = 'PATH_NOT_ABSOLUTE'; throw e; }
  return p;
}

export function execArgv(cmd, args) {
  assertArg(cmd);
  for (const a of args) assertArg(a);
  return execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
}

/** `command -v` with the name passed as a parameter, not concatenated into the script. */
export function commandOnPath(name) {
  if (typeof name !== 'string' || !/^[A-Za-z0-9._+-]+$/.test(name)) return false;
  const r = spawnSync('sh', ['-c', 'command -v "$1"', 'sh', name], { stdio: ['ignore', 'pipe', 'pipe'] });
  return r.status === 0;
}

export function writableLines(roots, { maxDepth = null, limit = 5 } = {}) {
  const lines = [];
  for (const root of roots) {
    const args = [assertAbsolutePath(root)];
    if (maxDepth != null) args.push('-maxdepth', String(maxDepth));
    args.push('!', '-type', 'l', '(', '-perm', '-o+w', '-o', '-perm', '-g+w', ')', '-print');
    let text = '';
    try { text = execArgv('find', args); }
    catch (e) {
      // find exits non-zero on unreadable entries; keep what it printed AND record the failure, so an empty report can
      // no longer be mistaken for "nothing writable" (PR #28 condition on #21).
      text = e.stdout ? e.stdout.toString() : '';
      lines.push(`FIND_FAILED ${root} (${e.code ?? e.status ?? 'error'})`);
      if (lines.length >= limit) return lines;
    }
    for (const line of text.split('\n')) {
      if (!line) continue;
      lines.push(line);
      if (lines.length >= limit) return lines;
    }
  }
  return lines;
}

export function statOwners(paths) {
  if (!paths.length) return '';
  return execArgv('stat', ['-c', '%U %a', '--', ...paths.map(assertAbsolutePath)]);
}

export function codeWritableReport({ roots, statPaths = [], maxDepth = 6 }) {
  const lines = writableLines(roots, { maxDepth, limit: 5 });
  const stats = statOwners(statPaths);
  return (lines.length ? lines.join('\n') + '\n' : '') + stats;
}

/** POSIX single quotes for the mount-namespace launcher, which still needs a shell to chain mounts. */
export function shellSingleQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}
