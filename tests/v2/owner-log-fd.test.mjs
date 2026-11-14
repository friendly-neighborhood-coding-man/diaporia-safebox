import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, symlinkSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OwnerSimulator } from '../../src/v2/supervisor/owner.mjs';

test('owner log view reads an append-only file and refuses a symlink', () => {
  const d = mkdtempSync(join(tmpdir(), 'olog-'));
  const log = join(d, 'owner-log.jsonl');
  const sim = new OwnerSimulator({ now: () => 1_700_000_000_000, logPath: log });
  sim.policy('owner_alice');
  const view = OwnerSimulator.view(log);
  assert.equal(view.policies.size, 1);
  const cap = sim.issueCapability({ recipientId: 'merchant-a.mock', maxAmountYocto: '1', taskRef: 't' });
  view.refresh();
  assert.equal(view.issued.has(cap.cap.capId), true);
  view.refresh();
  assert.equal(view.issued.size, 1);
  const other = join(d, 'other.jsonl');
  writeFileSync(other, JSON.stringify({ type: 'POLICY', policy: { policyId: 'forged' } }) + '\n');
  const link = join(d, 'link.jsonl');
  symlinkSync(other, link);
  assert.throws(() => OwnerSimulator.view(link), (e) => e.code === 'OWNER_LOG_SYMLINK');
  rmSync(d, { recursive: true, force: true });
});
