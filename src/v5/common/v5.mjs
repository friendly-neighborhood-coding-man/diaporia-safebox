// SafeBox V5 primitives: domain-separated SHA-256 digests (V3 canonical encoding), Ed25519 signatures under V5 domains,
// HMAC pseudonyms and AES-256-GCM sealing for journal metadata. Only established primitives from node:crypto / OpenSSL.
// No custom randomness, no custom hash, no raw key concatenation: a signature is always Ed25519(domain || digest).
import { createHash, createHmac, createCipheriv, createDecipheriv, createPublicKey, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { canon, fail, b64u, fromB64u, ED_PREFIX, edPublicId } from '../../v3/common/canon.mjs';

export const PROTOCOL5 = 'safebox.v5';
export const V5_DOMAINS = Object.freeze({
  GENESIS: 'DIAPORIA_SAFEBOX_V5_GENESIS\n',
  GENESIS_EXT: 'DIAPORIA_SAFEBOX_V5_GENESIS_EXTENSION\n',
  COMMAND: 'DIAPORIA_SAFEBOX_V5_COMMAND_STATEMENT\n',       // what a credential signs for ANY V5 authority-bearing command
  AUTH_STATE: 'DIAPORIA_SAFEBOX_V5_AUTHORITY_STATE\n',
  SUMMARY: 'DIAPORIA_SAFEBOX_V5_COMMAND_SUMMARY\n',
  HOLD: 'DIAPORIA_SAFEBOX_V5_PROTECTIVE_HOLD\n',
  RAPID_REQUEST: 'DIAPORIA_SAFEBOX_V5_RAPID_USE_REQUEST\n',
  RISK_ENGINE: 'DIAPORIA_SAFEBOX_V5_RISK_ENGINE_DECISION\n', // deterministic engine attestations (delay / rapid-use termination)
  DELEGATION: 'DIAPORIA_SAFEBOX_V5_DELEGATED_CAPABILITY\n',
  DELEGATED_OP: 'DIAPORIA_SAFEBOX_V5_DELEGATED_OPERATION\n',  // the delegate (AI agent) key signs each execution request
  CONTACT: 'DIAPORIA_SAFEBOX_V5_VERIFIED_CONTACT\n',
  JOURNAL_EVENT: 'DIAPORIA_SAFEBOX_V5_JOURNAL_EVENT\n',
  JOURNAL_CHECKPOINT: 'DIAPORIA_SAFEBOX_V5_JOURNAL_CHECKPOINT\n',
  REPORT: 'DIAPORIA_SAFEBOX_V5_SECURITY_REPORT\n',
  FINDING: 'DIAPORIA_SAFEBOX_V5_ANALYST_FINDING\n',
  PSEUDONYM: 'DIAPORIA_SAFEBOX_V5_PSEUDONYM\n',
});
const DSET = new Set(Object.values(V5_DOMAINS));
const dom = (d) => { if (!DSET.has(d)) fail('UNKNOWN_V5_DOMAIN'); return Buffer.from(d); };

export const sha256hex = (b) => createHash('sha256').update(b).digest('hex');
/** d5(domain, obj) = SHA-256(domain || canonical(obj)). */
export const d5 = (domain, obj) => createHash('sha256').update(Buffer.concat([dom(domain), Buffer.from(canon(obj))])).digest();
export const d5hex = (domain, obj) => d5(domain, obj).toString('hex');
export const nonce256 = () => randomBytes(32).toString('hex');

function edKey(pubId) {
  if (typeof pubId !== 'string' || !pubId.startsWith(ED_PREFIX)) fail('BAD_PUBLIC_KEY');
  const raw = fromB64u(pubId.slice(ED_PREFIX.length));
  if (raw.length !== 32) fail('BAD_PUBLIC_KEY');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64u(raw) }, format: 'jwk' });
}
/** Opaque Ed25519 signer for V5 statements (private key never leaves the closure, never serialized). */
export function newSigner5(label = 'ed25519') {
  const { privateKey } = generateKeyPairSync('ed25519');
  const publicKey = edPublicId(privateKey);
  return Object.freeze({
    label, publicKey,
    signObj(domain, obj) { return b64u(sign(null, Buffer.concat([dom(domain), Buffer.from(canon(obj))]), privateKey)); },
    signDigest(domain, dig) { return b64u(sign(null, Buffer.concat([dom(domain), Buffer.from(dig)]), privateKey)); },
    toJSON() { return { label, publicKey }; },
  });
}
export function verifyObj5(domain, obj, sig, pub) {
  try { const s = fromB64u(sig); if (s.length !== 64) return false; return verify(null, Buffer.concat([dom(domain), Buffer.from(canon(obj))]), edKey(pub), s); } catch { return false; }
}
export function verifyDigest5(domain, dig, sig, pub) {
  try { const s = fromB64u(sig); if (s.length !== 64) return false; return verify(null, Buffer.concat([dom(domain), Buffer.from(dig)]), edKey(pub), s); } catch { return false; }
}
/** V3 device signers sign raw (domain || bytes): sign a V5 digest with a V3 Ed25519 device key under a V5 domain. */
export const signDigest5With = (v3signer, domain, dig) => v3signer.signDigest(dom(domain).toString(), dig);

/** Keyed pseudonym (HMAC-SHA-256). Same input -> same pseudonym within one deployment; not reversible without the key. */
export function pseudonymizer(key = randomBytes(32)) {
  return (kind, value) => 'p_' + createHmac('sha256', key).update(V5_DOMAINS.PSEUDONYM + kind + '\u0000' + String(value)).digest('hex').slice(0, 20);
}
/** AES-256-GCM sealing of sensitive metadata (key per retention period: deleting the key crypto-shreds that period). */
export function seal(key, obj, aad) {
  const iv = randomBytes(12); const c = createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(obj))), c.final()]);
  return { iv: b64u(iv), ct: b64u(ct), tag: b64u(c.getAuthTag()) };
}
export function unseal(key, s, aad) {
  const d = createDecipheriv('aes-256-gcm', key, fromB64u(s.iv)); d.setAAD(Buffer.from(aad)); d.setAuthTag(fromB64u(s.tag));
  return JSON.parse(Buffer.concat([d.update(fromB64u(s.ct)), d.final()]).toString());
}
export const H = 3600_000, D = 86_400_000;
