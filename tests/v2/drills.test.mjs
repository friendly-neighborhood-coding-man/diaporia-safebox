// Supervised drills: crash/restart recovery, audit-log failure, budgets, races, freeze integrity, clock and policy integrity.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { world, legitPropose, ledgerTransfers, codeOf, y, MERCHANTS } from './support.mjs';
import { FileClockReader } from '../../src/v2/common/clock.mjs';
import { newSigner, V2_DOMAINS } from '../../src/v2/common/crypto.mjs';
import { SafeBoxError } from '../../src/v1/canonical.mjs';

/** Wraps the zone's ledger client to inject crashes/lost responses. */
function faultyLedger(w, plan) {
  const real = w.ledgerExec; let n = 0;
  w.zone.ledger = { async call(op, args) {
    if (op === 'SUBMIT_TX') { const k = n++; const f = plan[k];
      if (f === 'drop-before') throw new SafeBoxError('IPC_CLOSED');            // crash before the ledger saw it
      if (f === 'drop-after') { await real.call(op, args); throw new SafeBoxError('IPC_TIMEOUT'); } // ledger applied it, response lost
    }
    return real.call(op, args); } };
}

test('crash before ledger submit: restart reconciles by re-submitting the SAME signed bytes; exactly one effect', async () => {
  const w = await world();
  const p = await legitPropose(w);
  faultyLedger(w, ['drop-before']);
  await w.advance(11 * 60_000, 11 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'UNKNOWN');
  const before = w.zone.store.get(p.paymentId).tx_statement;
  w.restartSensitive();
  await w.advance(60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'SETTLED');
  const tx = await ledgerTransfers(w);
  assert.equal(tx.length, 1); assert.equal(tx[0].statement, before);
});

test('crash after ledger applied the transfer (lost response): recovery finds it, no double settlement', async () => {
  const w = await world();
  const p = await legitPropose(w);
  faultyLedger(w, ['drop-after']);
  await w.advance(11 * 60_000, 11 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'UNKNOWN');
  w.restartSensitive();
  for (let i = 0; i < 3; i++) { await w.advance(60_000); w.restartSensitive(); }
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'SETTLED');
  assert.equal((await ledgerTransfers(w)).length, 1);
  assert.equal((await w.ledgerRead.call('BALANCES', {}))[MERCHANTS[0]], y(1));
});

test('superseded key nonce: a never-accepted transfer is re-signed (same payment, same one-use nonce) and settles once', async () => {
  const w = await world();
  const a = await legitPropose(w); w.clock.advance(1000); const b = await legitPropose(w, { recipientId: MERCHANTS[1] });
  faultyLedger(w, ['drop-before', 'ok']);
  await w.advance(11 * 60_000, 11 * 60_000); // A lost, B accepted with higher key nonce
  assert.equal((await w.gz.call('STATUS', { paymentId: a.paymentId })).state, 'UNKNOWN');
  await w.advance(60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: a.paymentId })).state, 'SETTLED');
  assert.equal((await w.gz.call('STATUS', { paymentId: b.paymentId })).state, 'SETTLED');
  const tx = await ledgerTransfers(w);
  assert.equal(tx.length, 2);
  assert.ok(w.zone.store.journalRows().some(j => j.detail.includes('RESIGN_AFTER_PROOF_NOT_INCLUDED')));
  assert.equal((await w.watchdog.scan()).verification.unauthorized, 0);
});

test('re-signed transfer and ledger dedup: same intent nonce can never be accepted twice', async () => {
  const w = await world();
  const p = await legitPropose(w);
  await w.advance(11 * 60_000);
  const row = w.zone.store.get(p.paymentId);
  const res = await w.ledgerExec.call('SUBMIT_TX', { tx: { statement: row.tx_statement, signature: row.tx_signature } });
  assert.equal(res.duplicate, true);
  const forged = JSON.parse(row.tx_statement); forged.keyNonce = '99';
  const s2 = w.executor.sign(V2_DOMAINS.LEDGER_TX, forged); // even the REAL executor key cannot pay the same intent twice
  assert.equal(await codeOf(w.ledgerExec.call('SUBMIT_TX', { tx: s2 })), 'LEDGER_INTENT_NONCE_USED');
  assert.equal((await ledgerTransfers(w)).length, 1);
});

test('audit log failure fails closed: no proposal accepted, no release, no ledger effect; recovers when audit returns', async () => {
  let fault = false;
  const w = await world({ auditFault: () => fault });
  fault = true;
  assert.equal(await codeOf(legitPropose(w)), 'AUDIT_UNAVAILABLE');
  assert.equal(w.zone.payments().length, 0);
  fault = false;
  const p = await legitPropose(w);
  fault = true;
  w.clock.advance(11 * 60_000); w.wallClock.t += 1; await w.ctl.call('HEARTBEAT', {});
  await assert.rejects(w.ctl.call('TICK', {}), /AUDIT_UNAVAILABLE/);
  assert.equal((await ledgerTransfers(w)).length, 0);
  assert.equal(w.zone.store.get(p.paymentId).state, 'BUFFERED');
  fault = false;
  await w.advance(60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'SETTLED');
});

test('budget limits are enforced by the Sensitive Zone (pending count, pending exposure, cumulative, executions, duration)', async () => {
  const w = await world({ policyOver: { maxPendingCount: '3', maxPendingExposureYocto: y(5), maxCumulativeYocto: y(8), maxExecutions: '5' } });
  for (let i = 0; i < 3; i++) await legitPropose(w);
  assert.match(String(await legitPropose(w).catch(e => e.message)), /PENDING_COUNT_LIMIT/);
  await w.advance(11 * 60_000);
  await legitPropose(w, { amount: y(3) }); await legitPropose(w, { amount: y(2) });
  assert.match(String(await legitPropose(w, { amount: y(1) }).catch(e => e.message)), /PENDING_EXPOSURE_LIMIT|CUMULATIVE_LIMIT|EXECUTION_COUNT_LIMIT/);
  await w.advance(11 * 60_000);
  assert.match(String(await legitPropose(w, { amount: y(1) }).catch(e => e.message)), /CUMULATIVE_LIMIT|EXECUTION_COUNT_LIMIT/);
  w.clock.advance(27 * 3600_000);
  assert.match(String(await legitPropose(w).catch(e => e.message)), /POLICY_NOT_ACTIVE/);
  const v = await w.watchdog.scan();
  assert.equal(v.verification.unauthorized, 0);
});

test('durable single-use capability across OS processes: 6 processes race the same capability, exactly one reservation', async () => {
  const w = await world();
  const { signed } = w.owner.issueCapability({ recipientId: MERCHANTS[0], maxAmountYocto: y(1), taskRef: 'task_race' });
  const cfgPath = join(w.dir, 'race.json');
  writeFileSync(cfgPath, JSON.stringify({ db: join(w.dir, 'sensitive.db'), cfg: w.cfg, now: w.now(), signed, ledgerDb: join(w.dir, 'ledger.db') }));
  const child = new URL('../support/v2-race-child.mjs', import.meta.url).pathname;
  const outs = await Promise.all(Array.from({ length: 6 }, () => new Promise(res => { const p = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', child, cfgPath]); let o = ''; p.stdout.on('data', d => o += d); p.on('exit', () => res(o.trim())); })));
  assert.equal(outs.filter(o => o === 'OK').length, 1, outs.join(','));
  assert.equal(w.zone.payments().length, 1);
});

test('freeze integrity: forged / unbound / stale unfreeze statements are refused; proposals denied while frozen', async () => {
  const w = await world();
  await w.watchdog.contain('CONFIRMED_BREACH', 'drill', []);
  assert.match(String(await legitPropose(w).catch(e => e.message)), /FREEZE_ACTIVE/);
  const since = (await w.ctl.call('STATE', {})).control.since;
  const evil = newSigner('evil');
  const forged = evil.sign(V2_DOMAINS.UNFREEZE, { v: 'safebox.v2.unfreeze', target: 'sensitive-zone', frozenAt: since, reviewRef: 'x_review', issuedAt: new Date(w.now()).toISOString() });
  assert.equal(await codeOf(w.ctl.call('UNFREEZE', { unfreeze: forged })), 'BAD_SIGNATURE');
  assert.equal(await codeOf(w.ctl.call('UNFREEZE', { unfreeze: w.owner.unfreeze('sensitive-zone', '123', 'stale_review') })), 'UNFREEZE_NOT_BOUND_TO_THIS_FREEZE');
  assert.equal(await codeOf(w.ctl.call('UNFREEZE', { unfreeze: w.owner.unfreeze('mock-ledger', since, 'wrong_target') })), 'UNFREEZE_NOT_BOUND_TO_THIS_FREEZE');
  assert.equal(await codeOf(w.ctl.call('HOLD', { reason: 'x', classification: 'y' })), 'OK');
  assert.equal((await w.ctl.call('STATE', {})).control.level, 'FROZEN', 'HOLD never downgrades a freeze');
  assert.equal((await w.ledgerRead.call('STATE', {})).frozen, true);
});

test('anomaly (payments stuck UNKNOWN) => HOLD (no releases) => cleared after review', async () => {
  const w = await world();
  const a = await legitPropose(w);
  w.zone.ledger = { call: async () => { throw new SafeBoxError('IPC_CLOSED'); } };
  await w.advance(11 * 60_000);
  const b = await legitPropose(w);
  await w.advance(4 * 60_000);
  assert.equal((await w.ctl.call('STATE', {})).control.level, 'HOLD');
  assert.ok(w.freezeStore.records.some(r => r.type === 'ANOMALY' && r.code.startsWith('PAYMENTS_STUCK_UNKNOWN')));
  w.zone.ledger = w.ledgerExec;
  await w.advance(12 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: a.paymentId })).state, 'SETTLED');
  assert.equal((await w.gz.call('STATUS', { paymentId: b.paymentId })).state, 'SETTLED');
  assert.equal((await w.ctl.call('STATE', {})).control.level, 'NONE');
  assert.equal(w.freezeStore.isFrozen(), false, 'an unconfirmed anomaly is not classified as a breach');
});

test('policy integrity: attacker-signed or below-floor policies are refused even on the control channel', async () => {
  const w = await world();
  const evil = newSigner('evil');
  const p = JSON.parse(w.owner.policy('owner_alice').statement); p.policyId = 'pol_evil'; p.ownerKey = evil.publicKey;
  assert.equal(await codeOf(w.ctl.call('LOAD_POLICY', { policy: evil.sign(V2_DOMAINS.POLICY, p) })), 'BAD_SIGNATURE');
  assert.equal(await codeOf(w.ctl.call('LOAD_POLICY', { policy: w.owner.policy('owner_alice', { policyId: 'pol_fast', bufferMs: '1000' }) })), 'POLICY_BUFFER_BELOW_FLOOR');
  assert.equal(await codeOf(w.gz.call('LOAD_POLICY', { policy: w.owner.policy('owner_alice', { policyId: 'pol_x' }) })), 'OP_DENIED');
});

test('virtual clock readers refuse a clock that moves backwards or is missing (fail closed)', async () => {
  const w = await world();
  const f = join(w.dir, 'clock');
  writeFileSync(f, '2000'); const r = new FileClockReader(f);
  assert.equal(r.now(), 2000);
  writeFileSync(f, '1000'); assert.throws(() => r.now(), /CLOCK_BACKWARDS/);
  writeFileSync(f, 'garbage'); assert.throws(() => r.now(), /CLOCK_INVALID/);
  assert.throws(() => new FileClockReader(join(w.dir, 'nope')).now(), /CLOCK_UNAVAILABLE/);
});

test('in-process repair loop: injected flaw -> breach -> freeze -> patch -> replay/mutations denied -> regression -> recover -> resume', async () => {
  const { runInProcess, inProcessRepair } = await import('../../src/v2/harness.mjs');
  const h = inProcessRepair(); // regression gate skipped in unit context (the OS drill runs the full suite)
  const r = await runInProcess({ seed: 'unit-repair', hours: 3, mode: 'B', injectFlaw: 'SKIP_RECIPIENT_BINDING', techniques: ['recipient_substitution'],
    worldOpts: { watchdogOpts: { preReleaseAudit: false, drillHideFlawFlag: true } }, onFrozen: h });
  const rep = h.repairs.find(x => x.resumed);
  assert.ok(rep, JSON.stringify(h.repairs.map(x => x.gates)));
  assert.equal(r.result.summary.unauthorizedLedgerTransfers, 1, 'exactly the single pre-detection drill effect');
  assert.ok(r.result.rows.filter(x => x.label === 'normal' && x.t > r.result.stoppedAt.t).some(x => x.observed === 'SETTLED_AS_INTENDED'), 'legit traffic resumes');
});

test('pre-release audit (buffer use) catches the same injected flaw with ZERO ledger effect', async () => {
  const { runInProcess } = await import('../../src/v2/harness.mjs');
  const r = await runInProcess({ seed: 'unit-preaudit', hours: 3, mode: 'B', injectFlaw: 'SKIP_RECIPIENT_BINDING', techniques: ['recipient_substitution'],
    worldOpts: { watchdogOpts: { preReleaseAudit: true, drillHideFlawFlag: true } } });
  assert.ok(r.freezeRecords.some(f => f.type === 'FREEZE' && f.reason.includes('PRE_RELEASE_AUDIT_MISMATCH')));
  assert.equal(r.result.summary.unauthorizedLedgerTransfers, 0);
});
