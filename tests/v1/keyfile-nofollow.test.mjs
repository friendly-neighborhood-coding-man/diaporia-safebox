// Synthetic keys in disposable files. No network and no account with funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, symlinkSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyPair } from 'near-api-js';
import { writeFileSync } from 'node:fs';
import { writeOwnerKeyFile, loadOwnerSigner } from '../../src/v1/authz.mjs';
import { loadExecutorSigner } from '../../src/v1/near/executor.mjs';

test('owner and executor key loads refuse a symlink and a permissive mode', () => {
  const d = mkdtempSync(join(tmpdir(), 'kfile-'));
  const owner = join(d, 'owner.json');
  writeOwnerKeyFile(owner, 'owner-synthetic');
  const ownerLink = join(d, 'owner-link.json');
  symlinkSync(owner, ownerLink);
  assert.throws(() => loadOwnerSigner(ownerLink), (e) => e.code === 'OWNER_KEY_FILE_SYMLINK');
  assert.equal(typeof loadOwnerSigner(owner).publicKey, 'string');
  chmodSync(owner, 0o644);
  assert.throws(() => loadOwnerSigner(owner), (e) => e.code === 'OWNER_KEY_FILE_TOO_PERMISSIVE');

  const kp = KeyPair.fromRandom('ed25519');
  const exec = join(d, 'exec.json');
  writeFileSync(exec, JSON.stringify({ account_id: 'mock.synthetic', public_key: kp.getPublicKey().toString(), private_key: kp.toString() }), { mode: 0o600 });
  const execLink = join(d, 'exec-link.json');
  symlinkSync(exec, execLink);
  assert.throws(() => loadExecutorSigner(execLink, 'mock.synthetic'), (e) => e.code === 'EXECUTOR_KEY_FILE_SYMLINK');
  assert.equal(loadExecutorSigner(exec, 'mock.synthetic').accountId, 'mock.synthetic');
  rmSync(d, { recursive: true, force: true });
});
