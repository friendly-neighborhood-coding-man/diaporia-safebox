// WebAuthn (Level 2/3) relying-party verification for SafeBox administrative entry points.
// What this proves: the private key of a registered credential signed authenticatorData || SHA-256(clientDataJSON) for
// THIS challenge (= the exact action digest), THIS origin and THIS RP ID, and that the authenticator reported user
// presence (UP) and user verification (UV). UV means the authenticator verified the user locally (PIN, pattern or
// biometric); WebAuthn does NOT tell the relying party which method was used, so SafeBox never claims a biometric was
// checked, never receives biometric data, and never accepts a caller-supplied boolean such as biometricVerified.
import { createPublicKey, verify as cverify } from 'node:crypto';
import { decodeCbor } from './cbor.mjs';
import { fail, sha256, b64u, fromB64u, exactFields } from '../common/canon.mjs';

const FLAG_UP = 0x01, FLAG_UV = 0x04, FLAG_BE = 0x08, FLAG_BS = 0x10, FLAG_AT = 0x40, FLAG_ED = 0x80;

export function parseAuthData(buf) {
  const b = Buffer.from(buf);
  if (b.length < 37) fail('WEBAUTHN_AUTHDATA_SHORT');
  const out = { rpIdHash: b.subarray(0, 32), flags: b[32], signCount: b.readUInt32BE(33) };
  out.up = !!(out.flags & FLAG_UP); out.uv = !!(out.flags & FLAG_UV); out.be = !!(out.flags & FLAG_BE); out.bs = !!(out.flags & FLAG_BS);
  if (out.bs && !out.be) fail('WEBAUTHN_FLAGS_INCONSISTENT');
  let p = 37;
  if (out.flags & FLAG_AT) {
    if (b.length < p + 18) fail('WEBAUTHN_AUTHDATA_SHORT');
    out.aaguid = b.subarray(p, p + 16).toString('hex'); p += 16;
    const n = b.readUInt16BE(p); p += 2;
    if (n < 16 || n > 1023 || b.length < p + n) fail('WEBAUTHN_CREDID');
    out.credentialId = b.subarray(p, p + n); p += n;
    const { value, end } = decodeCbor(b.subarray(p), { allowTrailing: true });
    out.coseKey = value; p += end;
  }
  if (out.flags & FLAG_ED) fail('WEBAUTHN_EXTENSIONS_NOT_ALLOWED');
  if (p !== b.length) fail('WEBAUTHN_AUTHDATA_TRAILING');
  return out;
}

/** COSE EC2 P-256 (alg -7, ES256) or OKP Ed25519 (alg -8) -> SPKI DER base64url + alg. */
export function coseToSpki(cose) {
  if (!(cose instanceof Map)) fail('WEBAUTHN_COSE');
  const kty = cose.get(1), alg = cose.get(3);
  if (kty === 2 && alg === -7 && cose.get(-1) === 1) {
    const x = cose.get(-2), y = cose.get(-3);
    if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) fail('WEBAUTHN_COSE');
    const k = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) }, format: 'jwk' });
    return { alg: 'ES256', spki: b64u(k.export({ format: 'der', type: 'spki' })) };
  }
  if (kty === 1 && alg === -8 && cose.get(-1) === 6) {
    const x = cose.get(-2); if (!Buffer.isBuffer(x) || x.length !== 32) fail('WEBAUTHN_COSE');
    const k = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64u(x) }, format: 'jwk' });
    return { alg: 'EdDSA', spki: b64u(k.export({ format: 'der', type: 'spki' })) };
  }
  // V6 closeout: RSA (alg -257, RS256 / RSASSA-PKCS1-v1_5 SHA-256), which Windows Hello platform authenticators may use
  if (kty === 3 && alg === -257) {
    const n = cose.get(-1), e = cose.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e) || n.length < 256 || n.length > 512 || e.length < 1 || e.length > 8) fail('WEBAUTHN_COSE');
    const k = createPublicKey({ key: { kty: 'RSA', n: b64u(n), e: b64u(e) }, format: 'jwk' });
    return { alg: 'RS256', spki: b64u(k.export({ format: 'der', type: 'spki' })) };
  }
  fail('WEBAUTHN_UNSUPPORTED_ALG');
}

function parseClientData(clientDataJSON, expectType) {
  const raw = fromB64u(clientDataJSON, 'clientDataJSON');
  if (raw.length > 2048) fail('WEBAUTHN_CLIENTDATA_TOO_LARGE');
  let cd; try { cd = JSON.parse(raw.toString('utf8')); } catch { fail('WEBAUTHN_CLIENTDATA_JSON'); }
  if (!cd || typeof cd !== 'object' || Array.isArray(cd)) fail('WEBAUTHN_CLIENTDATA_JSON');
  if (cd.type !== expectType) fail('WEBAUTHN_WRONG_TYPE');
  return { cd, raw };
}

/**
 * Registration ceremony (attestation "none" or "packed" self-attestation). Returns the credential record to pin.
 * rp: { rpId, origin }. expectedChallenge: Buffer (enrollment challenge bound to the enrollment action).
 */
export function verifyRegistration({ attestationObject, clientDataJSON }, { rp, expectedChallenge, requireUV = true }) {
  const { cd, raw } = parseClientData(clientDataJSON, 'webauthn.create');
  if (cd.challenge !== b64u(expectedChallenge)) fail('WEBAUTHN_CHALLENGE_MISMATCH');
  if (cd.origin !== rp.origin) fail('WEBAUTHN_ORIGIN_MISMATCH');
  if (cd.crossOrigin === true) fail('WEBAUTHN_CROSS_ORIGIN');
  const att = decodeCbor(fromB64u(attestationObject, 'attestationObject'));
  if (!(att instanceof Map) || typeof att.get('fmt') !== 'string' || !Buffer.isBuffer(att.get('authData')) || !(att.get('attStmt') instanceof Map)) fail('WEBAUTHN_ATTESTATION');
  const ad = parseAuthData(att.get('authData'));
  if (!ad.rpIdHash.equals(sha256(Buffer.from(rp.rpId)))) fail('WEBAUTHN_RPID_MISMATCH');
  if (!ad.up) fail('WEBAUTHN_NO_USER_PRESENCE');
  if (requireUV && !ad.uv) fail('WEBAUTHN_NO_USER_VERIFICATION');
  if (!ad.credentialId || !ad.coseKey) fail('WEBAUTHN_NO_ATTESTED_CREDENTIAL');
  const key = coseToSpki(ad.coseKey);
  const fmt = att.get('fmt');
  let attestation = 'none';
  if (fmt === 'packed') {
    const st = att.get('attStmt');
    if (st.has('x5c')) fail('WEBAUTHN_ATTESTATION_CERT_UNSUPPORTED'); // full attestation chains are out of scope (no trust anchors)
    if ((st.get('alg') === -7 ? 'ES256' : st.get('alg') === -8 ? 'EdDSA' : st.get('alg') === -257 ? 'RS256' : null) !== key.alg) fail('WEBAUTHN_ATTESTATION_ALG');
    if (!sigOk(key, Buffer.concat([att.get('authData'), sha256(raw)]), st.get('sig'))) fail('WEBAUTHN_ATTESTATION_SIGNATURE');
    attestation = 'self';
  } else if (fmt !== 'none') fail('WEBAUTHN_ATTESTATION_FORMAT');
  return { credentialId: b64u(ad.credentialId), alg: key.alg, spki: key.spki, aaguid: ad.aaguid, signCount: ad.signCount,
    backupEligible: ad.be, backedUp: ad.bs, attestation, uvAtRegistration: ad.uv };
}

function sigOk(key, data, sig) {
  if (!Buffer.isBuffer(sig)) return false;
  try {
    const pk = createPublicKey({ key: fromB64u(key.spki), format: 'der', type: 'spki' });
    if (key.alg === 'ES256') return cverify('sha256', data, { key: pk, dsaEncoding: 'der' }, sig);
    if (key.alg === 'RS256') return pk.asymmetricKeyType === 'rsa' && pk.asymmetricKeyDetails.modulusLength >= 2048 && cverify('sha256', data, pk, sig);
    return cverify(null, data, pk, sig);
  } catch { return false; }
}

export const ASSERTION_FIELDS = ['credentialId', 'authenticatorData', 'clientDataJSON', 'signature'];

/**
 * Assertion for ONE specific action. The challenge must equal the action digest; the stored signCount must increase
 * (clone detection) unless the authenticator reports 0 consistently. Returns {signCount, uv}.
 */
export function verifyAssertion(assertion, { rp, expectedChallenge, credential, requireUV = true }) {
  exactFields(assertion, ASSERTION_FIELDS, ['userHandle'], 'WEBAUTHN_ASSERTION_FIELDS');
  if (assertion.credentialId !== credential.credentialId) fail('WEBAUTHN_CREDENTIAL_MISMATCH');
  const { cd, raw } = parseClientData(assertion.clientDataJSON, 'webauthn.get');
  if (cd.challenge !== b64u(expectedChallenge)) fail('WEBAUTHN_CHALLENGE_MISMATCH');
  if (cd.origin !== rp.origin) fail('WEBAUTHN_ORIGIN_MISMATCH');
  if (cd.crossOrigin === true) fail('WEBAUTHN_CROSS_ORIGIN');
  if ('tokenBinding' in cd && cd.tokenBinding?.status === 'present') fail('WEBAUTHN_TOKEN_BINDING_UNSUPPORTED');
  const adBuf = fromB64u(assertion.authenticatorData, 'authenticatorData');
  const ad = parseAuthData(adBuf);
  if (ad.credentialId) fail('WEBAUTHN_UNEXPECTED_ATTESTED_DATA');
  if (!ad.rpIdHash.equals(sha256(Buffer.from(rp.rpId)))) fail('WEBAUTHN_RPID_MISMATCH');
  if (!ad.up) fail('WEBAUTHN_NO_USER_PRESENCE');
  if (requireUV && !ad.uv) fail('WEBAUTHN_NO_USER_VERIFICATION');
  if (!sigOk(credential, Buffer.concat([adBuf, sha256(raw)]), fromB64u(assertion.signature, 'signature'))) fail('WEBAUTHN_BAD_SIGNATURE');
  const prev = Number(credential.signCount ?? 0);
  if ((ad.signCount !== 0 || prev !== 0) && ad.signCount <= prev) fail('WEBAUTHN_SIGNCOUNT_NOT_INCREASING');
  return { signCount: ad.signCount, uv: ad.uv, up: ad.up };
}
