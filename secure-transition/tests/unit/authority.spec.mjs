// Security Authority logic against the real MOCK ledger class (in-process here; the OS-separated deployment is tested in
// tests/os). Every request below is an ordinary API request; the Authority decides.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { Authority, initialState, policyDigest } from '../../src/authority/authority.mjs';
import { Ledger } from '../../src/ledger/ledger.mjs';
import { OwnerDevice } from '../../src/deploy/owner.mjs';
import { newKeyPair, signEnvelope, DOMAINS, digestObj } from '../../src/common/crypto.mjs';
import { tmp } from './helpers.mjs';

export function world(t, { ledgerUp = () => true } = {}) {
  const d = tmp(t); const ad = join(d, 'auth'); const ld = join(d, 'ledger'); mkdirSync(ad); mkdirSync(ld);
  const acct = newKeyPair(); const witness = newKeyPair(); const owner = new OwnerDevice();
  writeFileSync(join(ad, 'account.key'), acct.privatePem);
  const L = new Ledger(ld); L.init({ accounts: { 'safebox.mock': { balance: '1000', publicPem: acct.publicPem }, 'merchant-a.mock': { balance: '0' } } });
  const purpose = { id: 'groceries', version: 1, recipients: ['merchant-a.mock'], perTxMax: '50', budget: '200' };
  writeFileSync(join(ad, 'state.json'), JSON.stringify(initialState({ accountId: 'safebox.mock', accountPub: acct.publicPem, ownerPub: owner.owner.publicPem, recoveryPub: owner.recovery.publicPem, witnessPub: witness.publicPem, purpose, release: { version: 1, sha256: 'a'.repeat(64) } })));
  const ledger = async (m, p) => {
    if (!ledgerUp()) throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' });
    if (m === 'submit') return L.submit(p.env); if (m === 'status') return { ok: true, ...L.status(p.txid) };
    if (m === 'history') return { ok: true, history: L.history(p.from) }; if (m === 'account') return { ok: true, account: L.account(p.id) };
  };
  const A = new Authority({ dir: ad, ledger });
  const att = (payload) => signEnvelope(DOMAINS.WITNESS, payload, witness.privatePem, witness.publicPem);
  return { A, L, owner, acct, witness, att, ad, epoch: () => A.s.epoch };
}
const rejects = async (p, c) => { try { await p; assert.fail(`expected ${c}`); } catch (e) { assert.equal(e.code, c, e.message); } };
const rejectsSync = (f, c) => assert.throws(f, (e) => e.code === c, `expected ${c}`);

test('payment within Purpose is signed once and is idempotent on requestId', async (t) => {
  const { A, L } = world(t);
  const r = await A.pay({ requestId: 'req-00000001', to: 'merchant-a.mock', amount: '20' });
  assert.equal(r.status, 'BROADCAST');
  const again = await A.pay({ requestId: 'req-00000001', to: 'merchant-a.mock', amount: '20' });
  assert.equal(again.idempotent, true); assert.equal(again.txid, r.txid);
  await rejects(A.pay({ requestId: 'req-00000001', to: 'merchant-a.mock', amount: '21' }), 'REQUEST_ID_REUSED');
  L.tick(); assert.equal(L.account('merchant-a.mock').balance, '20'); assert.equal(A.s.spent, '20'); assert.equal(A.s.nextNonce, 2);
});

test('outside Purpose needs a bound, fresh, single-use owner approval', async (t) => {
  const { A, owner, epoch } = world(t);
  await rejects(A.pay({ requestId: 'req-00000002', to: 'attacker.mock', amount: '10' }), 'OWNER_APPROVAL_REQUIRED');
  await rejects(A.pay({ requestId: 'req-00000003', to: 'merchant-a.mock', amount: '51' }), 'OWNER_APPROVAL_REQUIRED');
  const ap = owner.cmd('APPROVE_PAYMENT', { requestId: 'req-00000004', to: 'shop-b.mock', amount: '60' }, { epoch: epoch() });
  await rejects(A.pay({ requestId: 'req-00000004', to: 'shop-b.mock', amount: '61', approval: ap }), 'APPROVAL_BINDING_MISMATCH');
  await rejects(A.pay({ requestId: 'req-00000005', to: 'shop-b.mock', amount: '60', approval: ap }), 'APPROVAL_BINDING_MISMATCH');
  assert.equal((await A.pay({ requestId: 'req-00000004', to: 'shop-b.mock', amount: '60', approval: ap })).status, 'BROADCAST');
  // Replay of the consumed approval for a new request id is refused.
  const ap2 = { envs: ap.envs.map(e => ({ ...e })) };
  await rejects(A.pay({ requestId: 'req-00000006', to: 'shop-b.mock', amount: '60', approval: ap2 }), 'OWNER_COMMAND_REPLAYED');
  const forged = owner.cmd('APPROVE_PAYMENT', { requestId: 'req-00000007', to: 'x.mock', amount: '9' }, { epoch: epoch(), roles: ['owner'], ownerKey: newKeyPair() });
  await rejects(A.pay({ requestId: 'req-00000007', to: 'x.mock', amount: '9', approval: forged }), 'OWNER_SIGNATURE_INVALID');
  const stale = owner.cmd('APPROVE_PAYMENT', { requestId: 'req-00000008', to: 'x.mock', amount: '9' }, { epoch: epoch() - 1 });
  await rejects(A.pay({ requestId: 'req-00000008', to: 'x.mock', amount: '9', approval: stale }), 'OWNER_COMMAND_STALE_EPOCH');
  const expired = owner.cmd('APPROVE_PAYMENT', { requestId: 'req-00000009', to: 'x.mock', amount: '9' }, { epoch: epoch(), ttlMs: -1 });
  await rejects(A.pay({ requestId: 'req-00000009', to: 'x.mock', amount: '9', approval: expired }), 'OWNER_COMMAND_EXPIRED');
});

test('budget is cumulative and never restored', async (t) => {
  const { A } = world(t);
  for (let i = 0; i < 4; i++) await A.pay({ requestId: `req-b000000${i}`, to: 'merchant-a.mock', amount: '50' });
  await rejects(A.pay({ requestId: 'req-b0000004', to: 'merchant-a.mock', amount: '1' }), 'OWNER_APPROVAL_REQUIRED');
  assert.equal(A.s.spent, '200');
});

test('maintenance refuses payments but FREEZE and recovery rotation still work', async (t) => {
  const { A, owner, epoch } = world(t);
  A.beginMaintenance({ transitionId: 'tr-0000001' });
  await rejects(A.pay({ requestId: 'req-m0000001', to: 'merchant-a.mock', amount: '1' }), 'MAINTENANCE_ACTIVE');
  rejectsSync(() => A.beginMaintenance({ transitionId: 'tr-0000002' }), 'TRANSITION_IN_PROGRESS');
  A.ownerCommand(owner.cmd('FREEZE', { reason: 'test' }, { epoch: epoch(), roles: ['recovery'] }));
  assert.ok(A.s.frozen);
  const next = new OwnerDevice();
  A.ownerCommand(owner.cmd('ROTATE_OWNER', { newOwnerPub: next.owner.publicPem }, { epoch: epoch(), roles: ['recovery'] }));
  rejectsSync(() => A.ownerCommand(owner.cmd('UNFREEZE', {}, { epoch: epoch(), roles: ['owner', 'recovery'] })), 'OWNER_CREDENTIAL_REVOKED');
  rejectsSync(() => A.ownerCommand(owner.cmd('AUTHORIZE_UPDATE', { targetName: 'a', version: 2, sha256: 'b'.repeat(64), length: 1 }, { epoch: epoch() })), 'OWNER_CREDENTIAL_REVOKED');
});

test('policy governance: no app-callable policy setter; permissive migration needs owner+recovery; stale digest refused', (t) => {
  const { A, owner, epoch } = world(t);
  const purpose = { id: 'groceries', version: 2, recipients: ['merchant-a.mock', 'attacker.mock'], perTxMax: '50', budget: '200' };
  rejectsSync(() => A.ownerCommand(owner.cmd('POLICY_MIGRATION', { fromPolicyDigest: policyDigest(A.s), purpose }, { epoch: epoch() })), 'OWNER_QUORUM_NOT_MET');
  const tighter = { id: 'groceries', version: 2, recipients: ['merchant-a.mock'], perTxMax: '10', budget: '100' };
  rejectsSync(() => A.ownerCommand(owner.cmd('POLICY_MIGRATION', { fromPolicyDigest: 'f'.repeat(64), purpose: tighter }, { epoch: epoch() })), 'POLICY_MIGRATION_STALE');
  A.ownerCommand(owner.cmd('POLICY_MIGRATION', { fromPolicyDigest: policyDigest(A.s), purpose: tighter }, { epoch: epoch() }));
  assert.equal(A.s.purpose.perTxMax, '10'); assert.equal(A.s.epoch, 2);
  rejectsSync(() => A.ownerCommand(owner.cmd('POLICY_MIGRATION', { fromPolicyDigest: policyDigest(A.s), schema: 2 }, { epoch: epoch() })), 'OWNER_QUORUM_NOT_MET');
  rejectsSync(() => A.ownerCommand(owner.cmd('APPROVE_UPDATE_ROOT', { rootDigest: 'c'.repeat(64) }, { epoch: epoch() })), 'OWNER_QUORUM_NOT_MET');
  rejectsSync(() => A.ownerCommand(owner.cmd('SET_WITNESS', { witnessPub: 'x' }, { epoch: epoch() })), 'OWNER_QUORUM_NOT_MET');
  const c = owner.cmd('FREEZE', {}, { epoch: epoch() }); A.ownerCommand(c);
  rejectsSync(() => A.ownerCommand(c), 'OWNER_COMMAND_REPLAYED');
});

test('update authorization respects the version floor; completion needs a reconciled, witness-attested transition', async (t) => {
  const { A, owner, epoch, att } = world(t);
  rejectsSync(() => A.ownerCommand(owner.cmd('AUTHORIZE_UPDATE', { targetName: 'a', version: 1, sha256: 'b'.repeat(64), length: 1 }, { epoch: epoch() })), 'VERSION_BELOW_FLOOR');
  A.ownerCommand(owner.cmd('AUTHORIZE_UPDATE', { targetName: 'a', version: 2, sha256: 'b'.repeat(64), length: 1 }, { epoch: epoch() }));
  A.beginMaintenance({ transitionId: 'tr-0000003' });
  const good = { kind: 'READY', transitionId: 'tr-0000003', rolledBack: false, release: { version: 2, sha256: 'b'.repeat(64) }, policyDigest: policyDigest(A.s), epoch: A.s.epoch };
  rejectsSync(() => A.completeTransition({ transitionId: 'tr-0000003', attestation: att(good) }), 'RECONCILE_REQUIRED');
  await A.reconcile({ transitionId: 'tr-0000003' });
  rejectsSync(() => A.completeTransition({ transitionId: 'tr-0000003', attestation: signEnvelope(DOMAINS.WITNESS, good, newKeyPair().privatePem, newKeyPair().publicPem) }), 'WITNESS_ATTESTATION_INVALID');
  rejectsSync(() => A.completeTransition({ transitionId: 'tr-0000003', attestation: att({ ...good, release: { version: 3, sha256: 'b'.repeat(64) } }) }), 'RELEASE_NOT_OWNER_AUTHORIZED');
  rejectsSync(() => A.completeTransition({ transitionId: 'tr-0000003', attestation: att({ ...good, transitionId: 'tr-other00' }) }), 'WITNESS_ATTESTATION_MISMATCH');
  A.completeTransition({ transitionId: 'tr-0000003', attestation: att(good) });
  assert.equal(A.s.versionFloor, 2); assert.equal(A.s.maintenance, null);
});

test('reconcile: pending payments keep settling during maintenance; unknown txs are rebroadcast once', async (t) => {
  let up = true; const { A, L } = world(t, { ledgerUp: () => up });
  await A.pay({ requestId: 'req-r0000001', to: 'merchant-a.mock', amount: '5' });     // broadcast, pending
  up = false; await A.pay({ requestId: 'req-r0000002', to: 'merchant-a.mock', amount: '6' }); up = true; // signed, never reached ledger
  A.beginMaintenance({ transitionId: 'tr-0000004' });
  L.tick();                                                    // the chain settles r1 although SafeBox is in maintenance
  const r = await A.reconcile({ transitionId: 'tr-0000004' });
  assert.deepEqual(r.report.settled, ['req-r0000001']); assert.deepEqual(r.report.rebroadcast, ['req-r0000002']);
  L.tick(); const r2 = await A.reconcile({ transitionId: 'tr-0000004' });
  assert.deepEqual(r2.report.settled, ['req-r0000002']); assert.equal(r2.report.rebroadcast.length, 0);
  assert.equal(L.account('merchant-a.mock').balance, '11'); assert.equal(L.history('safebox.mock').length, 2);
});

test('reconcile fails closed when the ledger shows activity the Authority never signed', async (t) => {
  const { A, L } = world(t);
  A.beginMaintenance({ transitionId: 'tr-0000005' });
  // Ledger anomaly injected directly into ledger state (no signing): a settled tx this Authority has no record of.
  L.s.txs['f'.repeat(64)] = { status: 'SETTLED', height: 99, tx: { from: 'safebox.mock', to: 'elsewhere.mock', amount: '1', nonce: 1 } }; L.s.accounts['safebox.mock'].nonce = 1;
  const r = await A.reconcile({ transitionId: 'tr-0000005' });
  assert.equal(r.error, 'KEY_COMPROMISE_SUSPECTED'); assert.ok(A.s.frozen); assert.ok(A.s.safeHold);
});

test('property: random request sequences never decrease counters or exceed policy', async (t) => {
  const { A, L, owner, epoch } = world(t);
  let seed = 777; const rnd = (n) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % n);
  const recips = ['merchant-a.mock', 'attacker.mock', 'shop-b.mock'];
  let prev = { nonce: A.s.nextNonce, spent: 0n, epoch: A.s.epoch, consumed: 0 };
  for (let i = 0; i < 400; i++) {
    const op = rnd(7);
    try {
      if (op <= 2) await A.pay({ requestId: `req-p${String(rnd(60)).padStart(7, '0')}`, to: recips[rnd(3)], amount: String(1 + rnd(80)) });
      else if (op === 3) A.beginMaintenance({ transitionId: `tr-p${rnd(3)}000000` });
      else if (op === 4 && A.s.maintenance) { await A.reconcile({ transitionId: A.s.maintenance.transitionId }); A.s.maintenance = null; A.save(); }
      else if (op === 5) A.ownerCommand(owner.cmd(rnd(2) ? 'FREEZE' : 'UNFREEZE', {}, { epoch: epoch(), roles: rnd(2) ? ['owner', 'recovery'] : ['owner'] }));
      else L.tick(rnd(3));
    } catch (e) { assert.ok(e.code, String(e)); }
    const cur = { nonce: A.s.nextNonce, spent: BigInt(A.s.spent), epoch: A.s.epoch, consumed: Object.keys(A.s.consumedOwnerNonces).length };
    assert.ok(cur.nonce >= prev.nonce && cur.spent >= prev.spent && cur.epoch >= prev.epoch && cur.consumed >= prev.consumed, `regression at step ${i}`);
    assert.ok(cur.spent <= 200n, 'budget exceeded without owner approval');
    for (const p of Object.values(A.s.payments)) assert.equal(p.to === 'merchant-a.mock' || p.ownerApproved, true);
    prev = cur;
  }
  L.tick(); const settledTo = L.history('safebox.mock').filter(h => h.status === 'SETTLED');
  assert.ok(settledTo.every(h => h.tx.to === 'merchant-a.mock'));
  assert.equal(new Set(settledTo.map(h => h.tx.memo)).size, settledTo.length, 'a request id settled twice');
});
