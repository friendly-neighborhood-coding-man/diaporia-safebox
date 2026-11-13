import test from 'node:test';
import assert from 'node:assert/strict';
import { world, legitPropose, ledgerTransfers, codeOf, y, MERCHANTS } from './support.mjs';
import { verifyLedgerEffects } from '../../src/v2/supervisor/verifier.mjs';

test('legitimate payment: PROPOSED->AUTHORIZED->RESERVED->BUFFERED->RELEASED->SETTLED, verified independently', async () => {
  const w = await world();
  const p = await legitPropose(w, { amount: y(2) });
  assert.equal(p.state, 'BUFFERED');
  const states = w.zone.store.journalRows().filter(j => j.payment_id === p.paymentId).map(j => j.to_state);
  assert.deepEqual(states, ['PROPOSED', 'AUTHORIZED', 'RESERVED', 'BUFFERED']);
  assert.equal((await ledgerTransfers(w)).length, 0, 'no immediate financial effect');
  await w.advance(9 * 60_000);
  assert.equal((await ledgerTransfers(w)).length, 0, 'not before release time');
  await w.advance(2 * 60_000);
  const st = await w.gz.call('STATUS', { paymentId: p.paymentId });
  assert.equal(st.state, 'SETTLED');
  const tx = await ledgerTransfers(w);
  assert.equal(tx.length, 1); assert.equal(tx[0].recipient, MERCHANTS[0]); assert.equal(tx[0].amount, y(2));
  const v = verifyLedgerEffects({ transfers: tx, owner: w.owner, executorKey: w.executor.publicKey });
  assert.equal(v.unauthorizedCount, 0);
  assert.equal((await w.ledgerRead.call('BALANCES', {}))[MERCHANTS[0]], y(2));
});

test('buffer: release re-checks freeze; frozen payment is never released and is cancelled on unfreeze', async () => {
  const w = await world();
  const p = await legitPropose(w);
  await w.watchdog.contain('CONFIRMED_BREACH', 'drill', []);
  await w.advance(15 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'FROZEN');
  assert.equal((await ledgerTransfers(w)).length, 0);
  assert.equal(await codeOf(legitPropose(w)), 'POLICY_DENY');
  const r = await w.watchdog.recover({ reviewRef: 'rv_drill_1', diagnosis: 'drill' });
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'CANCELLED');
  await w.advance(15 * 60_000);
  assert.equal((await ledgerTransfers(w)).length, 0, 'cancelled payment never settles');
  const p2 = await legitPropose(w);
  await w.advance(11 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p2.paymentId })).state, 'SETTLED');
});

test('freeze persists across Sensitive Zone restart', async () => {
  const w = await world();
  const p = await legitPropose(w);
  await w.watchdog.contain('CONFIRMED_BREACH', 'drill', []);
  w.restartSensitive();
  assert.equal((await w.ctl.call('STATE', {})).control.level, 'FROZEN');
  await w.advance(20 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'FROZEN');
  assert.equal((await ledgerTransfers(w)).length, 0);
});

test('stale watchdog lease blocks release (fail closed) until heartbeat resumes', async () => {
  const w = await world();
  const p = await legitPropose(w);
  w.clock.advance(11 * 60_000);
  w.wallClock.t += 60_000; // watchdog silent for 60 s of real time
  await w.ctl.call('TICK', {});
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'BUFFERED');
  await w.advance(60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'SETTLED');
});

test('owner revocation during the buffer cancels the payment', async () => {
  const w = await world();
  const p = await legitPropose(w);
  await w.advance(3 * 60_000);
  const r = await w.ctl.call('REVOKE_CAP', { revocation: w.owner.revoke('owner_alice', p.cap.capId) });
  assert.equal(r.cancelled, p.paymentId);
  await w.advance(15 * 60_000);
  assert.equal((await ledgerTransfers(w)).length, 0);
});

test('delayed ledger settlement: RELEASED waits, then SETTLED exactly once', async () => {
  const w = await world({ settleDelayMs: 5 * 60_000 });
  const p = await legitPropose(w);
  await w.advance(11 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'RELEASED');
  await w.advance(6 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'SETTLED');
  assert.equal((await ledgerTransfers(w)).length, 1);
});

test('FP-001: a legitimate payment with a Unicode memo is not blocked (memo is never a decision input); control chars still refused', async () => {
  const w = await world();
  const p = await legitPropose(w, { memo: 'café ☕ order' });
  await w.advance(11 * 60_000);
  assert.equal((await w.gz.call('STATUS', { paymentId: p.paymentId })).state, 'SETTLED');
  assert.equal(await codeOf(legitPropose(w, { memo: 'line\nbreak' })), 'INVALID_MEMO');
});
