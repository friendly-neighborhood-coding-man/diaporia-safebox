// RS256 (COSE alg -257) WebAuthn support for Windows Hello platform authenticators: registration + assertion, and
// rejection of weak keys / wrong signatures. The rest of the RP checks are the unchanged V3 verifier.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash, randomBytes } from 'node:crypto';
import { encodeCbor } from '../../src/v3/webauthn/cbor.mjs';
import { verifyRegistration, verifyAssertion } from '../../src/v3/webauthn/verify.mjs';
import { b64u } from '../../src/v3/common/canon.mjs';

const sha = (b) => createHash('sha256').update(b).digest();
const RP = { rpId: 'localhost', origin: 'http://localhost:47610' };
function rsaAuth(bits = 2048) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const j = publicKey.export({ format: 'jwk' }); const credId = randomBytes(16); let counter = 0;
  const cose = new Map([[1, 3], [3, -257], [-1, Buffer.from(j.n, 'base64url')], [-2, Buffer.from(j.e, 'base64url')]]);
  const ad = (attested) => { const h = Buffer.concat([sha(Buffer.from(RP.rpId)), Buffer.from([0x05 | (attested ? 0x40 : 0)]), Buffer.alloc(4)]); h.writeUInt32BE(counter, 33);
    if (!attested) return h; const l = Buffer.alloc(2); l.writeUInt16BE(credId.length); return Buffer.concat([h, Buffer.alloc(16), l, credId, encodeCbor(cose)]); };
  return {
    register(challenge) { const cd = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: b64u(challenge), origin: RP.origin, crossOrigin: false }));
      return { attestationObject: b64u(encodeCbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', ad(true)]]))), clientDataJSON: b64u(cd) }; },
    assert(challenge, { tamper = false } = {}) { counter++; const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(challenge), origin: RP.origin, crossOrigin: false }));
      const a = ad(false); const sig = sign('sha256', Buffer.concat([a, sha(cd)]), privateKey); if (tamper) sig[10] ^= 1;
      return { credentialId: b64u(credId), authenticatorData: b64u(a), clientDataJSON: b64u(cd), signature: b64u(sig) }; },
  };
}

test('RS256 (Windows Hello style) registration and assertion verify; tampered signature and replayed counter fail', () => {
  const a = rsaAuth(); const ch = randomBytes(32);
  const cred = verifyRegistration(a.register(ch), { rp: RP, expectedChallenge: ch });
  assert.equal(cred.alg, 'RS256');
  const c2 = randomBytes(32); const as = a.assert(c2);
  const r = verifyAssertion(as, { rp: RP, expectedChallenge: c2, credential: cred }); assert.equal(r.uv, true);
  assert.throws(() => verifyAssertion(a.assert(c2, { tamper: true }), { rp: RP, expectedChallenge: c2, credential: { ...cred, signCount: r.signCount } }), /WEBAUTHN_BAD_SIGNATURE/);
  assert.throws(() => verifyAssertion(as, { rp: RP, expectedChallenge: c2, credential: { ...cred, signCount: r.signCount } }), /SIGNCOUNT/);
});

test('RS256 keys below 2048 bits are refused', () => {
  const a = rsaAuth(1024); const ch = randomBytes(32);
  assert.throws(() => verifyRegistration(a.register(ch), { rp: RP, expectedChallenge: ch }), /WEBAUTHN_COSE/);
});
