// SafeBox V4 primitives: domain-separated SHA-256 digests over the V3 canonical encoding, Ed25519 statement signing
// under V4 domains, a 256-bit CSPRNG nonce, and the V4 protocol identifier. Only established primitives are used
// (SHA-256, Ed25519, X25519, HKDF-SHA-256, AES-256-GCM from node:crypto / OpenSSL). No custom randomness or hashing.
import { createHash, createPublicKey, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { canon, fail, b64u, fromB64u, ED_PREFIX, edPublicId } from '../../v3/common/canon.mjs';

export const PROTOCOL = 'safebox.v4';
export const V4_DOMAINS = Object.freeze({
  GENESIS: 'DIAPORIA_SAFEBOX_V4_GENESIS\n',              // V4 chain id = H(v3 genesis digest, extension digest)
  GENESIS_EXT: 'DIAPORIA_SAFEBOX_V4_GENESIS_EXTENSION\n',
  INTENT: 'DIAPORIA_SAFEBOX_V4_AUTHORIZATION_INTENT\n',  // what an owner credential signs for a high-risk action
  SUMMARY: 'DIAPORIA_SAFEBOX_V4_AUTHORIZATION_SUMMARY\n',
  AUTH_STATE: 'DIAPORIA_SAFEBOX_V4_AUTHORITY_STATE\n',
  CHALLENGE: 'DIAPORIA_SAFEBOX_V4_CHALLENGE_GRANT\n',
  CONFIRM: 'DIAPORIA_SAFEBOX_V4_PROTECTED_CONFIRMATION\n', // simulated Android-Protected-Confirmation style key
  CONFIRM_POP: 'DIAPORIA_SAFEBOX_V4_CONFIRMER_POP\n',
  SCREEN: 'DIAPORIA_SAFEBOX_V4_SCREEN_EVIDENCE\n',
  ORC_POP: 'DIAPORIA_SAFEBOX_V4_OWNER_RECOVERY_POP\n',
  CASE: 'DIAPORIA_SAFEBOX_V4_RECOVERY_CASE\n',
  GOV_CASE: 'DIAPORIA_SAFEBOX_V4_GOVERNANCE_CASE\n',
  PARTICIPANT_POP: 'DIAPORIA_SAFEBOX_V4_PARTICIPANT_POP\n',
  VERDICT: 'DIAPORIA_SAFEBOX_V4_ADJUDICATION_VERDICT\n',
  BALLOT_COMMIT: 'DIAPORIA_SAFEBOX_V4_BALLOT_COMMITMENT\n',
  BALLOT_ELIG: 'DIAPORIA_SAFEBOX_V4_BALLOT_ELIGIBILITY\n',
  BALLOT_SEAL: 'DIAPORIA_SAFEBOX_V4_BALLOT_SEAL\n',
  TALLY: 'DIAPORIA_SAFEBOX_V4_TALLY_RESULT\n',
  LIVENESS: 'DIAPORIA_SAFEBOX_V4_LIVENESS\n',
  WITHDRAWAL: 'DIAPORIA_SAFEBOX_V4_PARTICIPANT_WITHDRAWAL\n',
});
const DSET = new Set(Object.values(V4_DOMAINS));
const dom = (d) => { if (!DSET.has(d)) fail('UNKNOWN_V4_DOMAIN'); return Buffer.from(d); };

export const sha256 = (b) => createHash('sha256').update(b).digest();
export const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
/** d4(domain, obj) = SHA-256(domain || canonical(obj)). */
export const d4 = (domain, obj) => sha256(Buffer.concat([dom(domain), Buffer.from(canon(obj))]));
export const d4hex = (domain, obj) => d4(domain, obj).toString('hex');
/** 256-bit challenge nonce from the OS CSPRNG. */
export const nonce256 = () => randomBytes(32).toString('hex');
export const keyDigest = (publicKey) => sha256hex(Buffer.from(String(publicKey)));

function edKey(pubId) {
  if (typeof pubId !== 'string' || !pubId.startsWith(ED_PREFIX)) fail('BAD_PUBLIC_KEY');
  const raw = fromB64u(pubId.slice(ED_PREFIX.length));
  if (raw.length !== 32) fail('BAD_PUBLIC_KEY');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64u(raw) }, format: 'jwk' });
}
/** Opaque Ed25519 signer for V4 statements (private key never leaves the closure). */
export function newSigner4(label = 'ed25519') {
  const { privateKey } = generateKeyPairSync('ed25519');
  const publicKey = edPublicId(privateKey);
  return Object.freeze({
    label, publicKey,
    signObj(domain, obj) { return b64u(sign(null, Buffer.concat([dom(domain), Buffer.from(canon(obj))]), privateKey)); },
    signDigest(domain, dig) { return b64u(sign(null, Buffer.concat([dom(domain), Buffer.from(dig)]), privateKey)); },
    toJSON() { return { label, publicKey }; },
  });
}
export function verifyObj(domain, obj, sig, pub) {
  try { const s = fromB64u(sig); if (s.length !== 64) return false; return verify(null, Buffer.concat([dom(domain), Buffer.from(canon(obj))]), edKey(pub), s); } catch { return false; }
}
export function verifyDigest(domain, dig, sig, pub) {
  try { const s = fromB64u(sig); if (s.length !== 64) return false; return verify(null, Buffer.concat([dom(domain), Buffer.from(dig)]), edKey(pub), s); } catch { return false; }
}
/** V3 Ed25519 device signers (K3/K5) sign raw (domain || digest); this lets them sign V4 intents under the V4 domain. */
export const signDigestWith = (v3signer, domain, dig) => v3signer.signDigest(dom(domain).toString(), dig);
/** V3 Ed25519 signers sign raw (domain || bytes): this produces a V4 statement signature verifiable by verifyObj. */
export const signObjWith = (v3signer, domain, obj) => v3signer.signDigest(dom(domain).toString(), Buffer.from(canon(obj)));
