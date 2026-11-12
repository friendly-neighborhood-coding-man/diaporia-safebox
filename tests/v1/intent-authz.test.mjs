// SEEN regression tests: WP1 canonical sealed intent + WP2 owner authorization.
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, domainDigestHex, DOMAINS, formatYocto, parseCanonical } from '../../src/v1/canonical.mjs';
import { buildIntent, sealIntent, parseSealedIntent, ACTIONS } from '../../src/v1/intent.mjs';
import { verifyAuthorization, authorizationStatement, parseMandate } from '../../src/v1/authz.mjs';
import { newOwner, T0, EXECUTOR, CONTRACT, MERCHANT, NEAR } from '../support/harness.mjs';

const mk = (over = {}) => buildIntent({ principalId: 'owner_alice', mandateId: 'm_alice', action: ACTIONS.CONTRACT, signerAccountId: EXECUTOR,
  contractId: CONTRACT, recipientId: MERCHANT, amountYocto: NEAR.toString(), ttlMs: 600_000, now: T0, ...over });

test('canonical encoding is key-order independent and domain separated', () => {
  assert.equal(canonicalJson({ b: '1', a: '2' }), canonicalJson({ a: '2', b: '1' }));
  assert.equal(canonicalJson({ b: '1', a: '2' }), '{"a":"2","b":"1"}');
  const c = '{"a":"1"}';
  assert.notEqual(domainDigestHex(DOMAINS.INTENT, c), domainDigestHex(DOMAINS.AUTHZ, c));
  assert.throws(() => canonicalJson({ a: 1 }), /CANONICAL_BAD_VALUE_TYPE/);
  assert.throws(() => canonicalJson({ a: 1.5 }), /CANONICAL_BAD_VALUE_TYPE/);
  assert.throws(() => canonicalJson({ a: null }), /CANONICAL_BAD_VALUE_TYPE/);
  assert.throws(() => canonicalJson({ a: 'mеrchant' }), /NON_ASCII/); // Cyrillic homoglyph
  assert.throws(() => parseCanonical('{"b":"1","a":"2"}'), /NOT_CANONICAL/);
  assert.throws(() => parseCanonical('{"a":"1","a":"2"}'), /NOT_CANONICAL/); // duplicate keys
});

test('sealed intent binds every execution field and round-trips', () => {
  const s = mk();
  assert.equal(s.intent.networkId, 'testnet');
  assert.equal(s.intent.receiverId, CONTRACT);
  assert.equal(s.intent.method, 'execute_payment');
  const again = parseSealedIntent(s.canonical);
  assert.equal(again.digest, s.digest);
  for (const [k, v] of Object.entries({ recipientId: 'attacker.testnet', amountYocto: '2' + s.intent.amountYocto.slice(1), nonce: 'f'.repeat(32), expiresAt: '2026-11-13T00:09:59.999Z' })) {
    assert.notEqual(sealIntent({ ...s.intent, [k]: v }).digest, s.digest, k);
  }
});

test('intent rejects unknown, missing, defaulted and incompatible fields', () => {
  const s = mk();
  assert.throws(() => sealIntent({ ...s.intent, memo: 'x' }), /UNEXPECTED_OR_MISSING_FIELD/);
  const { gas, ...noGas } = s.intent;
  assert.throws(() => sealIntent(noGas), /UNEXPECTED_OR_MISSING_FIELD/);
  assert.throws(() => sealIntent({ ...s.intent, networkId: 'mainnet' }), /WRONG_NETWORK/);
  assert.throws(() => sealIntent({ ...s.intent, recipientId: 'merchant.near' }), /NOT_A_TESTNET_ACCOUNT/);
  assert.throws(() => sealIntent({ ...s.intent, asset: 'USDC' }), /UNSUPPORTED_ASSET/);
  assert.throws(() => sealIntent({ ...s.intent, method: 'withdraw' }), /WRONG_METHOD/);
  assert.throws(() => sealIntent({ ...s.intent, attachedDepositYocto: '1' }), /WRONG_DEPOSIT/);
  assert.throws(() => sealIntent({ ...s.intent, amountYocto: '1.5' }), /INVALID_AMOUNT/);
  assert.throws(() => sealIntent({ ...s.intent, amountYocto: 1e24 }), /INVALID_AMOUNT/);
  assert.throws(() => sealIntent({ ...s.intent, amountYocto: '0100' }), /INVALID_AMOUNT/);
  assert.throws(() => sealIntent({ ...s.intent, amountYocto: '340282366920938463463374607431768211456' }), /u128/);
  assert.throws(() => sealIntent({ ...s.intent, action: 'NEAR_NATIVE_TRANSFER' }), /UNEXPECTED_OR_MISSING_FIELD/);
  assert.throws(() => sealIntent({ ...s.intent, expiresAt: '2026-11-14T00:00:00.000Z' }), /EXPIRY_WINDOW/);
  const n = mk({ action: ACTIONS.NATIVE });
  assert.throws(() => sealIntent({ ...n.intent, receiverId: 'attacker.testnet' }), /RECEIVER_RECIPIENT_MISMATCH/);
});

test('yocto formatting uses integer arithmetic only', () => {
  assert.equal(formatYocto('1'), '0.000000000000000000000001 NEAR');
  assert.equal(formatYocto('1500000000000000000000000'), '1.5 NEAR');
});

test('owner authorization verifies only for the exact digest, key, principal, challenge and window', () => {
  const s = mk();
  const owner = newOwner('owner_alice');
  const other = newOwner('owner_alice');
  const ch = 'cd'.repeat(32);
  const st = authorizationStatement({ sealed: s, challenge: ch, ownerKey: owner.publicKey, now: T0 });
  const { statement, signature } = owner.signStatement(DOMAINS.AUTHZ, st);
  const ok = (o = {}) => verifyAuthorization({ sealed: s, authorization: statement, signature, trustedOwnerKey: owner.publicKey, expectedChallenge: ch, now: T0 + 1000, ...o });
  assert.equal(ok().intentDigest, s.digest);
  assert.throws(() => ok({ trustedOwnerKey: other.publicKey }), /AUTHZ_KEY_NOT_TRUSTED/);
  assert.throws(() => ok({ expectedChallenge: 'ef'.repeat(32) }), /CHALLENGE_MISMATCH/);
  assert.throws(() => ok({ now: T0 + 5 * 60_000 }), /AUTHZ_EXPIRED/);
  assert.throws(() => ok({ sealed: mk() }), /AUTHZ_INTENT_MISMATCH/);
  const forged = other.signStatement(DOMAINS.AUTHZ, { ...st, ownerKey: owner.publicKey });
  assert.throws(() => ok({ signature: forged.signature }), /AUTHZ_BAD_SIGNATURE/);
  // Same key, same statement, but signed in a different domain (cross-protocol replay).
  const xdomain = owner.signStatement(DOMAINS.MANDATE, st);
  assert.throws(() => ok({ signature: xdomain.signature }), /AUTHZ_BAD_SIGNATURE/);
  assert.throws(() => ok({ signature: 'APPROVED_BY_OWNER' }), /AUTHZ_BAD_SIGNATURE/);
});

test('owner key never serialises its private part', () => {
  const owner = newOwner('owner_alice');
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(owner))).sort(), ['principalId', 'publicKey']);
});

test('mandate parser rejects inconsistent ceilings and non-testnet recipients', () => {
  const owner = newOwner('owner_alice');
  const base = { v: 'safebox.mandate.v1', mandateId: 'm_x', principalId: 'owner_alice', ownerKey: owner.publicKey, action: ACTIONS.CONTRACT,
    maxPerIntentYocto: '5', maxTotalYocto: '4', allowedRecipients: [MERCHANT], validFrom: '2026-11-13T00:00:00.000Z', expiresAt: '2026-11-14T00:00:00.000Z' };
  assert.throws(() => parseMandate(canonicalJson(base)), /MANDATE_INCONSISTENT/);
  assert.throws(() => parseMandate(canonicalJson({ ...base, maxPerIntentYocto: '1', allowedRecipients: ['x.near'] })), /NOT_A_TESTNET_ACCOUNT/);
});
