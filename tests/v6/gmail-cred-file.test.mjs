// Reconciled PR #22 tests on top of PR #26's descriptor-based loader. Synthetic OAuth fields only; no endpoint is contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, readFileSync, lstatSync, rmSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadGmailCredentials, writeGmailCredentialFile } from '../../src/v6/notify/gmail.mjs';

const CREDS = { client_id: 'cid.example', client_secret: 'cs-synthetic', refresh_token: '1//synthetic-refresh', sender: 'safebox.test@example.com' };
const POSIX = process.platform !== 'win32';
const dir = () => mkdtempSync(join(tmpdir(), 'gmcred-'));

test('credential load requires a regular 0600 file and refuses a symlink (POSIX)', { skip: !POSIX }, () => {
  const d = dir(); const p = join(d, 'gmail.json');
  writeFileSync(p, JSON.stringify(CREDS)); chmodSync(p, 0o644);
  assert.throws(() => loadGmailCredentials(p), (e) => e.code === 'GMAIL_CREDENTIALS_TOO_PERMISSIVE');
  chmodSync(p, 0o640);
  assert.throws(() => loadGmailCredentials(p), (e) => e.code === 'GMAIL_CREDENTIALS_TOO_PERMISSIVE');
  chmodSync(p, 0o600);
  assert.equal(loadGmailCredentials(p).sender, CREDS.sender);
  const link = join(d, 'link.json'); symlinkSync(p, link);
  assert.throws(() => loadGmailCredentials(link), (e) => e.code === 'GMAIL_CREDENTIALS_SYMLINK');
  rmSync(d, { recursive: true, force: true });
});

test('credential load: a FIFO at the path neither hangs nor loads (PR #26 O_NONBLOCK kept)', { skip: !POSIX }, () => {
  const d = dir(); const f = join(d, 'fifo.json');
  execFileSync('mkfifo', [f]);
  assert.throws(() => loadGmailCredentials(f), (e) => e.code === 'GMAIL_CREDENTIALS_INVALID');
  rmSync(d, { recursive: true, force: true });
});

test('credential write: exclusive create, mode 0600, refuses a symlink or dangling symlink, validates fields', { skip: !POSIX }, () => {
  const d = dir();
  const canary = join(d, 'canary'); writeFileSync(canary, 'CANARY');
  const link = join(d, 'gmail.json'); symlinkSync(canary, link);
  assert.throws(() => writeGmailCredentialFile(link, CREDS), (e) => e.code === 'GMAIL_CREDENTIALS_EXISTS');
  assert.equal(readFileSync(canary, 'utf8'), 'CANARY');
  assert.equal(lstatSync(link).isSymbolicLink(), true);
  const dangling = join(d, 'dangling.json'); symlinkSync(join(d, 'nowhere'), dangling);
  assert.throws(() => writeGmailCredentialFile(dangling, CREDS), (e) => e.code === 'GMAIL_CREDENTIALS_EXISTS');
  assert.equal(existsSync(join(d, 'nowhere')), false);
  for (const bad of ['', 'a\nb', 'x'.repeat(4097), 'tab\there', 'del\u007f']) {
    const q = join(d, 'bad-' + Math.random().toString(16).slice(2) + '.json');
    assert.throws(() => writeGmailCredentialFile(q, { ...CREDS, refresh_token: bad }), (e) => e.code === 'GMAIL_CREDENTIALS_INVALID');
    assert.equal(existsSync(q), false);
  }
  const p = join(d, 'new.json');
  writeGmailCredentialFile(p, CREDS);
  assert.equal(lstatSync(p).mode & 0o077, 0);
  assert.equal(loadGmailCredentials(p).refreshToken, CREDS.refresh_token);
  assert.throws(() => writeGmailCredentialFile(p, CREDS), (e) => e.code === 'GMAIL_CREDENTIALS_EXISTS');
  rmSync(d, { recursive: true, force: true });
});
