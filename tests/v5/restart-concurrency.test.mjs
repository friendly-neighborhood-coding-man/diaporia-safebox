// Restart safety and concurrent operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { buildV5, ok, deny, H, Y, burst, freezeBy, rapidRequest, rapidVote, rapidActivate } from './helpers.mjs';
import { RootService } from '../../src/v3/root/service.mjs';
import * as V5 from '../../src/v5/root/chain.mjs';
import { verifyWorld } from '../../src/v5/supervisor/verifier.mjs';

test('vault restart in the middle of an anomaly delay: delays, incidents and the bounded release survive', async () => {
  const w = buildV5();
  await burst(w, 4);
  const before = w.vault.v5payments().map(p => [p.payment_id, p.release_at, p.anomaly]);
  w.restartVault(); await w.pump();
  assert.deepEqual(w.vault.v5payments().map(p => [p.payment_id, p.release_at, p.anomaly]), before);
  assert.equal(w.vault.incidents().length, 1);
  await w.advance(30 * 60_000, 60_000);
  assert.ok(w.vault.v5payments().every(p => p.state === 'BUFFERED'), 'still delayed after restart');
  await w.advance(25 * H, 10 * 60_000);
  assert.ok(w.vault.v5payments().every(p => p.state === 'SETTLED'));
  assert.equal((await verifyWorld(w)).ok, true);
});

test('vault restart during Rapid-Use: the grant is re-derived from the Root replica, not from vault memory', async () => {
  const w = buildV5();
  await burst(w, 4);
  ok(await rapidRequest(w, 'k1-phone')); ok(await rapidVote(w, 'orc-1')); ok(await rapidVote(w, 'k3-root-hw'));
  w.restartVault();
  ok(await rapidActivate(w));
  await w.advance(11 * 60_000);
  assert.ok(w.vault.v5payments().every(p => p.state === 'SETTLED'));
});

test('Root crash after persisting a transition but before effects: replay restores the exact state, holds included', async () => {
  const w = buildV5();
  ok(await freezeBy(w, 'k1-phone', 'h1'));
  const db = join(w.dir, 'root.db');
  let crashed = false;
  const crashing = new RootService({ genesis: w.genesis, pinnedChainId: w.owner.chainId5, dbPath: db, now: w.now, chain: V5, crashAfterPersist: () => { crashed = true; throw new Error('crash'); } });
  const a = w.action('HOLD_CREATE', { holdId: 'h2', class: 'PROVISIONAL_HOLD', scope: { kind: 'GLOBAL', target: '*' }, reason: 'k2', durationMs: String(H) });
  assert.throws(() => crashing.submit({ action: a, approvals: w.owner.authorize5(crashing.state, a, ['k2-laptop'], { at: w.now() }) }), /crash/);
  assert.equal(crashed, true);
  w.restartRoot(); await w.pump();
  assert.deepEqual(w.effectiveHolds().map(h => h.holdId).sort(), ['h1', 'h2']);
  assert.equal(w.vault.root.seq, w.root.state.seq);
});

test('two Root writers on one store: the second append is a fork and is refused (compare-and-append)', async () => {
  const w = buildV5();
  const other = new RootService({ genesis: w.genesis, pinnedChainId: w.owner.chainId5, dbPath: join(w.dir, 'root.db'), now: w.now, chain: V5 });
  const a1 = w.action('HOLD_CREATE', { holdId: 'm1', class: 'PROVISIONAL_HOLD', scope: { kind: 'MERCHANT', target: 'merchant-a.mock' }, reason: 'x', durationMs: String(H) });
  const a2 = w.action('HOLD_CREATE', { holdId: 'm2', class: 'PROVISIONAL_HOLD', scope: { kind: 'MERCHANT', target: 'merchant-b.mock' }, reason: 'x', durationMs: String(H) });
  const r1 = { action: a1, approvals: w.owner.authorize5(w.root.state, a1, ['k1-phone'], { at: w.now() }) };
  const r2 = { action: a2, approvals: w.owner.authorize5(other.state, a2, ['k2-laptop'], { at: w.now() }) };
  w.root.submit(r1);
  assert.throws(() => other.submit(r2), /ROOT_CONCURRENT_APPEND|UNIQUE|constraint/);
});

test('concurrent payment proposals: the pending limit and Purpose limits hold under Promise.all', async () => {
  const w = buildV5();
  const rs = await Promise.all(Array.from({ length: 25 }, () => w.pay({ amountYocto: Y(5) })));
  assert.equal(rs.filter(r => r.ok).length, 16);
  assert.ok(rs.filter(r => !r.ok).every(r => /PENDING_COUNT_LIMIT/.test(r.error.detail ?? r.error.code)));
});

test('concurrent delegated operations with the same sequence number: exactly one is accepted', async () => {
  const w = buildV5();
  const k = w.owner.newDelegate('d1');
  ok(await w.cmd('DELEGATION_GRANT', { delegationId: 'd1', delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2), cumulativeMaxYocto: Y(50), maxUses: '20',
    expiresAt: w.iso(w.now() + 86_400_000), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'] }, ['k1-phone']));
  const ops = Array.from({ length: 5 }, () => w.delegateOp('d1', 7));
  const res = await Promise.all(ops.map(o => Promise.resolve().then(() => w.vault.proposeDelegated(o)).then(() => 'OK', e => e.code)));
  assert.equal(res.filter(x => x === 'OK').length, 1);
  assert.ok(res.filter(x => x !== 'OK').every(x => x === 'DELEGATED_OP_REPLAY'));
});

test('a stale approval prepared against an older Root state cannot land after a concurrent hold (authority digest)', async () => {
  const w = buildV5();
  const a = w.action('RAPID_USE_REQUEST', { requestId: 'rq-stale', scope: (await import('./helpers.mjs')).scopeOf(w), delayException: 'REMOVE_ANOMALY_DELAY', durationMs: String(H), explanation: 'urgent', incidentId: '-' });
  const ap = w.owner.authorize5(w.root.state, a, ['k1-phone'], { at: w.now() });
  ok(await freezeBy(w, 'k4-freeze', 'h1'));
  deny(await w.submit({ action: a, approvals: ap }), 'COMMAND_MISMATCH');
});
