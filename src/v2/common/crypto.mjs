// V2 signing helpers. Reuses the V1 canonical encoding and key-id format, but uses
// V2-only domain separators so no V2 statement can ever verify as a V1 statement (or vice versa).
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, createHash } from 'node:crypto';
import { canonicalJson, parseCanonical, fail } from '../../v1/canonical.mjs';
import { ownerKeyId, rawFromKeyId } from '../../v1/authz.mjs';

export const V2_DOMAINS = Object.freeze({
  POLICY: 'DIAPORIA_SAFEBOX_V2_POLICY\n',
  CAPABILITY: 'DIAPORIA_SAFEBOX_V2_TASK_CAPABILITY\n',
  REVOKE_CAP: 'DIAPORIA_SAFEBOX_V2_REVOKE_CAPABILITY\n',
  UNFREEZE: 'DIAPORIA_SAFEBOX_V2_UNFREEZE\n',
  LEDGER_TX: 'DIAPORIA_SAFEBOX_V2_MOCK_LEDGER_TX\n',
});

function domainBuf(domain, canonical) {
  if (!Object.values(V2_DOMAINS).includes(domain)) fail('UNKNOWN_DOMAIN');
  return Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from(canonical, 'utf8')]);
}

export const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
export const digestOf = (domain, canonical) => createHash('sha256').update(domainBuf(domain, canonical)).digest('hex');

function pubKeyObject(keyId) {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rawFromKeyId(keyId)).toString('base64url') }, format: 'jwk' });
}

export function keyIdOf(privateKeyObject) {
  return ownerKeyId(Buffer.from(createPublicKey(privateKeyObject).export({ format: 'jwk' }).x, 'base64url'));
}

/** Opaque signer: private key stays inside the closure; JSON serialisation exposes only the public key. */
export function makeSigner(privateKeyObject, label = 'signer') {
  const publicKey = keyIdOf(privateKeyObject);
  return Object.freeze({
    label, publicKey,
    sign(domain, statement) {
      const canonical = canonicalJson(statement);
      return { statement: canonical, signature: sign(null, domainBuf(domain, canonical), privateKeyObject).toString('base64') };
    },
    toJSON() { return { label, publicKey }; },
  });
}

export function newSigner(label) { return makeSigner(generateKeyPairSync('ed25519').privateKey, label); }

export function exportPkcs8(privateKeyObject) { return privateKeyObject.export({ format: 'der', type: 'pkcs8' }).toString('base64'); }
export function importPkcs8(b64) { return createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' }); }
export function generatePrivateKey() { return generateKeyPairSync('ed25519').privateKey; }

export function verifySig(domain, canonical, signatureB64, keyId) {
  if (typeof canonical !== 'string' || typeof signatureB64 !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signatureB64)) return false;
  try { return verify(null, domainBuf(domain, canonical), pubKeyObject(keyId), Buffer.from(signatureB64, 'base64')); }
  catch { return false; }
}

/** Parses + verifies a signed statement {statement, signature}; returns the parsed object. */
export function openSigned(domain, signed, keyId, maxBytes = 4096) {
  if (!signed || typeof signed !== 'object' || typeof signed.statement !== 'string' || typeof signed.signature !== 'string') fail('INVALID_SIGNED_STATEMENT');
  const obj = parseCanonical(signed.statement, maxBytes);
  if (!keyId) fail('NO_TRUSTED_KEY');
  if (!verifySig(domain, signed.statement, signed.signature, keyId)) fail('BAD_SIGNATURE');
  return obj;
}
