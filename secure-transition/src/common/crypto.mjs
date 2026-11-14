// SSTP V0 crypto helpers. No custom primitives: Ed25519 and SHA-256 come from Node's OpenSSL binding, canonical JSON
// from @tufjs/canonical-json (the encoder the TUF client uses). Every signature is domain-separated.
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { canonicalize } = require('@tufjs/canonical-json');

export const canon = (obj) => Buffer.from(canonicalize(obj));
export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
export const digestObj = (obj) => sha256(canon(obj));
export const randomId = (n = 16) => randomBytes(n).toString('hex');

export function newKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicRawHex: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('hex'),
  };
}

export const keyIdOf = (publicPem) => sha256(Buffer.from(publicPem.trim()));

/** Sign `payload` under `domain`. Returns { domain, payload, keyId, sig }. */
export function signEnvelope(domain, payload, privatePem, publicPem) {
  const msg = canon({ domain, payload });
  const sig = edSign(null, msg, createPrivateKey(privatePem)).toString('base64');
  return { domain, payload, keyId: keyIdOf(publicPem), sig };
}

/** Verify an envelope against an expected domain and one of the allowed public keys. Returns the matching pem or null. */
export function verifyEnvelope(env, domain, allowedPublicPems) {
  if (!env || typeof env !== 'object' || env.domain !== domain || typeof env.sig !== 'string') return null;
  const msg = canon({ domain, payload: env.payload });
  for (const pem of allowedPublicPems) {
    if (!pem || keyIdOf(pem) !== env.keyId) continue;
    try { if (edVerify(null, msg, createPublicKey(pem), Buffer.from(env.sig, 'base64'))) return pem; } catch { /* malformed */ }
  }
  return null;
}

export const DOMAINS = Object.freeze({
  OWNER: 'SSTP-V0/OWNER-COMMAND',
  RECOVERY: 'SSTP-V0/RECOVERY-COMMAND',
  WITNESS: 'SSTP-V0/WITNESS-ATTESTATION',
  LEDGER_TX: 'SSTP-V0/MOCK-LEDGER-TX',
});
