// Synthetic OAuth fields only. No token endpoint is contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, readFileSync, lstatSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadGmailCredentials, writeGmailCredentialFile } from '../../src/v6/notify/gmail.mjs';

const CREDS = { client_id: 'cid.example', client_secret: 'cs-synthetic', refresh_token: '1//synthetic-refresh', sender: 'safebox.test@example.com' };

function dir() { return mkdtempSync(join(tmpdir(), 'gmcred-')); }

test('credential load requires mode 0600 and a regular file', () => {
  const d = dir();
  const p = join(d, 'gmail.json');
  writeFileSync(p, JSON.stringify(CREDS), { mode: 0o644 });
  chmodSync(p, 0o644);
  assert.throws(() => loadGmailCredentials(p), (e) => e.code === 'GMAIL_CREDENTIALS_TOO_PERMISSIVE');
  chmodSync(p, 0o600);
  assert.equal(loadGmailCredentials(p).sender, CREDS.sender);
  const link = join(d, 'link.json');
  symlinkSync(p, link);
  assert.throws(() => loadGmailCredentials(link), (e) => e.code === 'GMAIL_CREDENTIALS_SYMLINK');
  rmSync(d, { recursive: true, force: true });
});

test('credential write creates mode 0600 and does not follow a symlink', () => {
  const d = dir();
  const canary = join(d, 'canary');
  writeFileSync(canary, 'CANARY');
  const link = join(d, 'gmail.json');
  symlinkSync(canary, link);
  assert.throws(() => writeGmailCredentialFile(link, CREDS), (e) => e.code === 'GMAIL_CREDENTIALS_EXISTS');
  assert.equal(readFileSync(canary, 'utf8'), 'CANARY');
  assert.equal(lstatSync(link).isSymbolicLink(), true);
  const p = join(d, 'new.json');
  writeGmailCredentialFile(p, CREDS);
  assert.equal(lstatSync(p).mode & 0o077, 0);
  assert.equal(loadGmailCredentials(p).refreshToken, CREDS.refresh_token);
  assert.throws(() => writeGmailCredentialFile(p, CREDS), (e) => e.code === 'GMAIL_CREDENTIALS_EXISTS');
  rmSync(d, { recursive: true, force: true });
});
