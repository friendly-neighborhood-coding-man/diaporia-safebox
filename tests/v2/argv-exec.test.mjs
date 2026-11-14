import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writableLines, shellSingleQuote, codeWritableReport, commandOnPath } from '../../src/v2/launch/argv-exec.mjs';

test('a directory name containing a shell separator is passed as one find argument', () => {
  const d = mkdtempSync(join(tmpdir(), 'argv-'));
  const name = `PWNED-${process.pid}`;
  const tricky = join(d, `a;touch ${name};#`);
  mkdirSync(tricky);
  try {
    const lines = writableLines([tricky], { maxDepth: 1, limit: 5 });
    assert.equal(existsSync(join(process.cwd(), name)), false);
    assert.ok(Array.isArray(lines));
  } finally {
    rmSync(join(process.cwd(), name), { force: true });
    rmSync(d, { recursive: true, force: true });
  }
});

test('shellSingleQuote keeps separators and quotes inside one shell word', () => {
  const marker = join(tmpdir(), 'argv-quote-pwned-' + process.pid);
  const q = shellSingleQuote(`a;touch ${marker};'`);
  const r = spawnSync('sh', ['-c', `printf %s ${q}`], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `a;touch ${marker};'`);
  assert.equal(existsSync(marker), false);
});

test('codeWritableReport stats the node binary without a shell', () => {
  const text = codeWritableReport({ roots: [join(process.cwd(), 'src/v2/launch')], statPaths: [process.execPath], maxDepth: 2 });
  assert.match(text, /\S+ \d+/);
  assert.equal(commandOnPath('sh'), true);
  assert.equal(commandOnPath('a;id'), false);
});
