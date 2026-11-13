// Delegated AI capabilities: exact scope (op class, recipients, asset, per-op, cumulative, uses, expiry, revocation conditions).
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildV5, ok, deny, H, D, Y, freezeBy } from './helpers.mjs';

const grant = async (w, id = 'd1', over = {}) => {
  const k = w.owner.newDelegate(id);
  return w.cmd('DELEGATION_GRANT', { delegationId: id, delegateKey: k.publicKey, operation: 'PAY', recipients: ['merchant-a.mock'], assets: ['NEAR'], perOpMaxYocto: Y(2),
    cumulativeMaxYocto: Y(5), maxUses: '4', expiresAt: w.iso(w.now() + 2 * D), revokeOn: ['EPOCH_CHANGE', 'ISSUER_RESTRICTED', 'PURPOSE_CHANGE'], ...over }, ['k1-phone']);
};
const pd = async (w, seq, opts = {}) => { try { return { ok: true, result: await w.payDelegated('d1', seq, opts) }; } catch (e) { return { ok: false, error: { code: e.code, detail: e.detail } }; } };

test('grant cannot exceed Purpose: recipients, asset, per-op, cumulative, TTL, mandatory revocation conditions', async () => {
  const w = buildV5();
  deny(await grant(w, 'x1', { recipients: ['attacker.mock'] }), 'DELEGATION_RECIPIENT_NOT_IN_PURPOSE');
  deny(await grant(w, 'x2', { perOpMaxYocto: Y(7) }), 'DELEGATION_PER_OP_EXCEEDS_PURPOSE');
  deny(await grant(w, 'x3', { expiresAt: w.iso(w.now() + 8 * D) }), 'DELEGATION_EXPIRY');
  deny(await grant(w, 'x4', { revokeOn: ['EPOCH_CHANGE'] }), 'DELEGATION_REVOKE_CONDITIONS');
  deny(await grant(w, 'x5', { assets: ['USDC'] }), 'DELEGATION_ASSET_NOT_IN_PURPOSE');
  deny(await grant(w, 'x6', { maxUses: '100000' }), 'DELEGATION_MAX_USES');
});

test('delegate pays inside scope; per-op, cumulative, max uses, recipient, replay and forged signature all refused', async () => {
  const w = buildV5();
  ok(await grant(w));
  ok(await pd(w, 1, { amountYocto: Y(2) }));
  deny(await pd(w, 2, { amountYocto: Y(3) }), 'OVER_DELEGATION_PER_OP');
  deny(await pd(w, 2, { recipientId: 'merchant-b.mock' }), 'RECIPIENT_NOT_IN_DELEGATION');
  deny(await pd(w, 1, { amountYocto: Y(1) }), 'DELEGATED_OP_REPLAY');
  ok(await pd(w, 2, { amountYocto: Y(2) }));
  deny(await pd(w, 3, { amountYocto: Y(2) }), 'OVER_DELEGATION_CUMULATIVE');
  ok(await pd(w, 3, { amountYocto: Y(1) }));
  deny(await pd(w, 4, { amountYocto: Y(1), key: w.owner.newDelegate('rogue') }), 'DELEGATED_OP_BAD_SIGNATURE');
  await w.advance(25 * H, 10 * 60_000); // 3 agent payments in a few seconds = cold-start burst -> bounded delay, then settlement
  assert.equal(w.vault.v5payments().filter(p => p.state === 'SETTLED').length, 3);
});

test('max uses exhausted', async () => {
  const w = buildV5();
  ok(await grant(w, 'd1', { cumulativeMaxYocto: Y(100), perOpMaxYocto: Y(1), maxUses: '2' }));
  ok(await pd(w, 1)); ok(await pd(w, 2));
  deny(await pd(w, 3), 'DELEGATION_MAX_USES_EXHAUSTED');
});

test('ends on: expiry, issuer restricted, explicit revoke, freeze, delegation hold', async () => {
  let w = buildV5(); ok(await grant(w)); await w.advance(2 * D + H, H); deny(await pd(w, 1), 'DELEGATION_NOT_ACTIVE');
  w = buildV5(); ok(await grant(w)); ok(await w.cmd('SUSPEND', { credId: 'k1-phone', holdId: 'q1' }, ['k2-laptop'])); deny(await pd(w, 1), 'DELEGATION_(NOT_ACTIVE|ISSUER_RESTRICTED)');
  w = buildV5(); ok(await grant(w)); ok(await w.cmd('DELEGATION_REVOKE', { delegationId: 'd1' }, ['k2-laptop'])); deny(await pd(w, 1), 'DELEGATION_NOT_ACTIVE');
  w = buildV5(); ok(await grant(w)); ok(await freezeBy(w, 'k4-freeze')); deny(await pd(w, 1), 'FREEZE_ACTIVE');
  w = buildV5(); ok(await grant(w)); ok(await w.cmd('HOLD_CREATE', { holdId: 'dh', class: 'TARGETED_QUARANTINE', scope: { kind: 'DELEGATION', target: 'd1' }, reason: 'agent looks odd', durationMs: String(H) }, ['k2-laptop']));
  deny(await pd(w, 1), 'DELEGATION_HOLD_ACTIVE');
  assert.equal((await w.pay({ credId: 'k2-laptop' })).ok, true, 'targeted: owner payments continue');
});

test('epoch change (credential revoked) ends every delegation', async () => {
  const w = buildV5(); ok(await grant(w));
  ok(await w.ownerAct('REVOKE', { credId: 'k4-freeze', reason: 'lost' }, ['k2-laptop', 'k3-root-hw']));
  assert.notEqual(w.root.state.v5.delegations.d1.status, 'ACTIVE');
  deny(await pd(w, 1), 'DELEGATION_NOT_ACTIVE');
});

test('a delegate burst is its own anomaly flow: delayed without touching the owner\'s own key flow', async () => {
  const w = buildV5(); ok(await grant(w, 'd1', { cumulativeMaxYocto: Y(100), perOpMaxYocto: Y(1), maxUses: '50' }));
  for (let i = 1; i <= 5; i++) { ok(await pd(w, i)); await w.advance(60_000); }
  const own = ok(await w.pay({ credId: 'k1-phone' }));
  assert.equal(own.anomaly, 'NONE');
  assert.ok(w.vault.v5payments().filter(p => p.flow === 'dg:d1').some(p => p.anomaly === 'ANOMALY_PAYMENT_DELAY'));
});
