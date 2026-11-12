import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalIntent, MockSafeBox} from '../src/mock/contract.mjs';

const intent = (overrides = {}) => ({
  principalId: 'owner_demo', action: 'MOCK_TRANSFER', recipientId: 'merchant.testnet',
  asset: 'TEST_NEAR', amountAtomic: '1000000000000000000000000',
  expiresAt: '2030-01-01T00:00:00.000Z', ...overrides
});
const clock = () => Date.parse('2026-11-13T00:00:00.000Z');

test('normal mock transfer executes once after matching mock approval', () => {
  const safe = new MockSafeBox({now: clock});
  const prepared = safe.prepare(intent());
  safe.recordMockApproval(prepared.id, {principalId: 'owner_demo', digest: prepared.digest});
  assert.equal(safe.executeOnce(prepared.id, prepared.intent).result, 'MOCK_EXECUTED');
  assert.equal(safe.mockEffects.length, 1);
  assert.throws(() => safe.executeOnce(prepared.id, prepared.intent), /ALREADY_USED/);
});

test('unapproved intent cannot execute', () => {
  const safe = new MockSafeBox({now: clock});
  const prepared = safe.prepare(intent());
  assert.throws(() => safe.executeOnce(prepared.id, prepared.intent), /NOT_APPROVED/);
});

test('recipient substitution fails after approval and does not execute', () => {
  const safe = new MockSafeBox({now: clock});
  const prepared = safe.prepare(intent());
  safe.recordMockApproval(prepared.id, {principalId: 'owner_demo', digest: prepared.digest});
  assert.throws(() => safe.executeOnce(prepared.id, intent({recipientId:'attacker.testnet'})), /TAMPERED/);
  assert.equal(safe.mockEffects.length, 0);
});

test('amount substitution fails after approval', () => {
  const safe = new MockSafeBox({now: clock});
  const prepared = safe.prepare(intent());
  safe.recordMockApproval(prepared.id, {principalId: 'owner_demo', digest: prepared.digest});
  assert.throws(() => safe.executeOnce(prepared.id, intent({amountAtomic:'2000000000000000000000000'})), /TAMPERED/);
});

test('approval is bound to prepared principal and digest', () => {
  const safe = new MockSafeBox({now: clock});
  const prepared = safe.prepare(intent());
  assert.throws(() => safe.recordMockApproval(prepared.id, {principalId:'another',digest:prepared.digest}), /MISMATCH/);
  assert.throws(() => safe.recordMockApproval(prepared.id, {principalId:'owner_demo',digest:'00'}), /MISMATCH/);
});

test('expired approval cannot execute', () => {
  let current = clock();
  const safe = new MockSafeBox({now: () => current});
  const prepared = safe.prepare(intent({expiresAt:'2026-11-13T00:01:00.000Z'}));
  safe.recordMockApproval(prepared.id, {principalId:'owner_demo',digest:prepared.digest});
  current += 61_000;
  assert.throws(() => safe.executeOnce(prepared.id, prepared.intent), /EXPIRED/);
});

test('strict contract rejects extra fields and malformed amounts', () => {
  assert.throws(() => canonicalIntent({...intent(), unrestrictedKey:'secret'}), /UNEXPECTED/);
  assert.throws(() => canonicalIntent(intent({amountAtomic:'1e24'})), /INVALID_AMOUNT/);
  assert.throws(() => canonicalIntent(intent({amountAtomic:'0'})), /INVALID_AMOUNT/);
});
