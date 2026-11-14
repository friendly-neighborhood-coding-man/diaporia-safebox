// Independent-review follow-ups on the legacy V1/V2 hardening (Mission 2): FIFO at a key/log path must not hang
// (F1), the incremental owner-log view is bound to one file (F9), a torn last line is not consumed (F14), and keygen
// keeps a concurrent winner's private key (link, not rename; F13). MOCK keys only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync, renameSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { OwnerSimulator } from '../../src/v2/supervisor/owner.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const posix = process.platform !== 'win32';
const url = (p) => pathToFileURL(join(REPO, p)).href;
// Run a snippet in a child with a hard timeout, so a regression shows up as a failed test instead of a hung suite.
const child = (code) => spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout: 15_000 });

test('a FIFO at the executor key path or the owner log path is refused, never blocks (review F1)', { skip: !posix }, (t) => {
  const d = mkdtempSync(join(tmpdir(), 'fifo-')); t.after(() => rmSync(d, { recursive: true, force: true }));
  for (const p of ['sens', 'sup', 'pub/sens', 'pub/sup']) mkdirSync(join(d, p), { recursive: true, mode: 0o700 });
  execFileSync('mkfifo', ['-m', '600', join(d, 'sens/executor.key')]);
  const kg = child(`import { generateZoneKeys } from ${JSON.stringify(url('src/v2/launch/keygen.mjs'))};
    try { generateZoneKeys(${JSON.stringify(d)}, 'sens', '0'); console.log('RETURNED'); } catch (e) { console.log(e.code); }`);
  assert.equal(kg.error?.code, undefined, 'keygen hung on a FIFO');
  assert.equal(kg.stdout.trim(), 'KEY_PATH_NOT_A_FILE');
  const log = join(d, 'owner-log.jsonl'); execFileSync('mkfifo', ['-m', '600', log]);
  const ow = child(`import { OwnerSimulator } from ${JSON.stringify(url('src/v2/supervisor/owner.mjs'))};
    const r = [];
    try { OwnerSimulator.view(${JSON.stringify(log)}); r.push('VIEW_RETURNED'); } catch (e) { r.push(e.code); }
    try { new OwnerSimulator({ now: () => 1, logPath: ${JSON.stringify(log)} }).policy('owner_alice'); r.push('WRITE_RETURNED'); } catch (e) { r.push(e.code); }
    console.log(r.join(','));`);
  assert.equal(ow.error?.code, undefined, 'owner log hung on a FIFO');
  assert.equal(ow.stdout.trim(), 'OWNER_LOG_NOT_A_FILE,OWNER_LOG_NOT_A_FILE');
});

test('the incremental owner-log view refuses a log replaced by another file between refreshes (review F9)', (t) => {
  const d = mkdtempSync(join(tmpdir(), 'olog-r-')); t.after(() => rmSync(d, { recursive: true, force: true }));
  const log = join(d, 'owner-log.jsonl');
  const sim = new OwnerSimulator({ now: () => 1_700_000_000_000, logPath: log });
  sim.policy('owner_alice');
  const view = OwnerSimulator.view(log);
  const forged = join(d, 'forged.jsonl');
  writeFileSync(forged, readFileSync(log, 'utf8') + JSON.stringify({ type: 'POLICY', policy: { policyId: 'forged' } }) + '\n', { mode: 0o600 });
  renameSync(forged, log);
  assert.throws(() => view.refresh(), (e) => e.code === 'OWNER_LOG_REPLACED');
  assert.equal(view.policies.has('forged'), false);
});

test('a torn last line is left for the next refresh and then applied once (review F14)', (t) => {
  const d = mkdtempSync(join(tmpdir(), 'olog-t-')); t.after(() => rmSync(d, { recursive: true, force: true }));
  const log = join(d, 'owner-log.jsonl');
  const sim = new OwnerSimulator({ now: () => 1_700_000_000_000, logPath: log });
  sim.policy('owner_alice');
  const view = OwnerSimulator.view(log); const off = view.offset;
  const rec = JSON.stringify({ type: 'REVOKE', capId: 'cap-1', at: 5 }) + '\n';
  appendFileSync(log, rec.slice(0, 10));
  view.refresh();
  assert.equal(view.offset, off); assert.equal(view.revoked.size, 0);
  appendFileSync(log, rec.slice(10));
  view.refresh();
  assert.equal(view.revoked.get('cap-1'), 5); assert.equal(view.offset, off + Buffer.byteLength(rec));
});

test('keygen keeps a concurrent winner\'s private key: the loser links, it never renames over it (review F13)', { skip: !posix }, () => {
  const d = mkdtempSync(join(tmpdir(), 'kg-race-'));
  try {
    for (const p of ['sens', 'sup', 'pub/sens', 'pub/sup']) mkdirSync(join(d, p), { recursive: true, mode: 0o700 });
    // The "winner" process creates the key at the exact moment between our readPrivate() == null and our publish step.
    const r = child(`import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
      const { generatePrivateKey, exportPkcs8, keyIdOf, importPkcs8 } = await import(${JSON.stringify(url('src/v2/common/crypto.mjs'))});
      const key = ${JSON.stringify(join(d, 'sens/executor.key'))}; const winner = generatePrivateKey();
      let armed = true; const plant = (b) => { if (armed && b === key) { armed = false; fs.writeFileSync(key, JSON.stringify({ v: 'sbx2.executor-key', synthetic: true, pkcs8: exportPkcs8(winner) }), { mode: 0o600 }); } };
      const L = fs.linkSync, R = fs.renameSync;
      fs.linkSync = function (a, b) { plant(String(b)); return L.call(this, a, b); };
      fs.renameSync = function (a, b) { plant(String(b)); return R.call(this, a, b); };
      syncBuiltinESMExports();
      const { generateZoneKeys } = await import(${JSON.stringify(url('src/v2/launch/keygen.mjs'))});
      const out = generateZoneKeys(${JSON.stringify(d)}, 'sens', '0');
      const disk = keyIdOf(importPkcs8(JSON.parse(fs.readFileSync(key, 'utf8')).pkcs8));
      console.log(JSON.stringify({ returnedWinner: out.publicKey === keyIdOf(winner), diskWinner: disk === keyIdOf(winner), planted: !armed }));`);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout.trim()), { returnedWinner: true, diskWinner: true, planted: true });
  } finally { rmSync(d, { recursive: true, force: true }); }
});
