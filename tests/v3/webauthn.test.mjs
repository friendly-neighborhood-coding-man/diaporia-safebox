// WebAuthn relying-party verification unit tests (byte-exact responses from the software authenticator).
import test from 'node:test';
import assert from 'node:assert/strict';
import { SoftAuthenticator } from '../../src/v3/webauthn/soft-authenticator.mjs';
import { verifyRegistration, verifyAssertion, parseAuthData } from '../../src/v3/webauthn/verify.mjs';
import { decodeCbor, encodeCbor } from '../../src/v3/webauthn/cbor.mjs';
import { b64u } from '../../src/v3/common/canon.mjs';

const rp = { rpId: 'safebox.local', origin: 'https://safebox.local' };
const ch = Buffer.alloc(32, 9);

test('registration: none and packed self-attestation verify; UV, origin, rpId and challenge are enforced', () => {
  for (const fmt of ['none', 'packed']) {
    const a = new SoftAuthenticator();
    const r = verifyRegistration(a.register({ ...rp, challenge: ch, fmt }), { rp, expectedChallenge: ch });
    assert.equal(r.alg, 'ES256'); assert.equal(r.attestation, fmt === 'none' ? 'none' : 'self');
  }
  const a = new SoftAuthenticator();
  assert.throws(() => verifyRegistration(a.register({ ...rp, challenge: ch, uv: false }), { rp, expectedChallenge: ch }), /NO_USER_VERIFICATION/);
  assert.throws(() => verifyRegistration(a.register({ rpId: 'evil.local', origin: rp.origin, challenge: ch }), { rp, expectedChallenge: ch }), /RPID_MISMATCH/);
  assert.throws(() => verifyRegistration(a.register({ rpId: rp.rpId, origin: 'https://evil.local', challenge: ch }), { rp, expectedChallenge: ch }), /ORIGIN_MISMATCH/);
  assert.throws(() => verifyRegistration(a.register({ ...rp, challenge: Buffer.alloc(32, 1) }), { rp, expectedChallenge: ch }), /CHALLENGE_MISMATCH/);
});

test('assertion: signature, counter, type and flags; UV is reported, never a biometric claim', () => {
  const a = new SoftAuthenticator();
  const reg = verifyRegistration(a.register({ ...rp, challenge: ch }), { rp, expectedChallenge: ch });
  const cred = { ...reg };
  const x = verifyAssertion(a.assert({ ...rp, challenge: ch }), { rp, expectedChallenge: ch, credential: cred });
  assert.equal(x.uv, true); assert.equal(Object.keys(x).includes('biometric'), false);
  cred.signCount = x.signCount;
  assert.throws(() => verifyAssertion(a.assert({ ...rp, challenge: ch, crossOrigin: true }), { rp, expectedChallenge: ch, credential: cred }), /CROSS_ORIGIN/);
  const b = new SoftAuthenticator();
  assert.throws(() => verifyAssertion({ ...b.assert({ ...rp, challenge: ch }), credentialId: a.credentialIdB64u }, { rp, expectedChallenge: ch, credential: cred }), /BAD_SIGNATURE|SIGNCOUNT/);
});

test('CBOR: strict decoding (trailing bytes, indefinite length, duplicate keys, depth)', () => {
  assert.deepEqual(decodeCbor(encodeCbor(new Map([[1, 2]]))), new Map([[1, 2]]));
  assert.throws(() => decodeCbor(Buffer.concat([encodeCbor(1), Buffer.from([0])])), /trailing/);
  assert.throws(() => decodeCbor(Buffer.from([0x9f, 0xff])), /indefinite/);
  assert.throws(() => decodeCbor(Buffer.from([0xa2, 0x01, 0x01, 0x01, 0x02])), /duplicate/);
  let deep = Buffer.from([0x01]); for (let i = 0; i < 12; i++) deep = Buffer.concat([Buffer.from([0x81]), deep]);
  assert.throws(() => decodeCbor(deep), /depth/);
  assert.throws(() => parseAuthData(Buffer.alloc(10)), /SHORT/);
  assert.ok(b64u);
});
