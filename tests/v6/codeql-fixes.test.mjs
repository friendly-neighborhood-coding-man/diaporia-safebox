// Regression tests for the CodeQL submission-freeze triage (security-fix/v6-codeql).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, symlinkSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadGmailCredentials } from '../../src/v6/notify/gmail.mjs';
import { termSafe } from '../../src/v6/common/term.mjs';

const CREDS = JSON.stringify({ client_id: 'c', client_secret: 's', refresh_token: 'r', sender: 'x@example.com' });

test('CQ-1 credentials: read through one descriptor; a symlink or a directory at the path is refused (POSIX)', { skip: process.platform === 'win32' }, () => {
  const d = mkdtempSync(join(tmpdir(), 'cq-')); const real = join(d, 'real.json'); writeFileSync(real, CREDS); chmodSync(real, 0o600);
  assert.equal(loadGmailCredentials(real).sender, 'x@example.com');
  const link = join(d, 'link.json'); symlinkSync(real, link);
  assert.throws(() => loadGmailCredentials(link), (e) => e.code === 'ELOOP');
  const dir = join(d, 'dir.json'); mkdirSync(dir);
  assert.throws(() => loadGmailCredentials(dir), (e) => e.code === 'GMAIL_CREDENTIALS_INVALID' || e.code === 'EISDIR');
  assert.throws(() => loadGmailCredentials(join(d, 'missing.json')), (e) => e.code === 'ENOENT');
});

test('CQ-2 terminal lines: CR/LF, ANSI escapes and bidi overrides cannot forge or recolour a demo terminal line', () => {
  const forged = 'memo\r\n[main] OK      payment APPROVED by owner\u001b[32m\u202e';
  const out = termSafe(forged);
  assert.ok(!/[\r\n\u001b\u202e]/.test(out));
  assert.equal(out, 'memo\\u000d\\n[main] OK      payment APPROVED by owner\\u001b[32m\\u202e');
  assert.equal(termSafe('plain 0.03 NEAR -> merchant-a.mock\ttab é 한'), 'plain 0.03 NEAR -> merchant-a.mock\ttab é 한');
  assert.equal(termSafe(42), '42');
});
