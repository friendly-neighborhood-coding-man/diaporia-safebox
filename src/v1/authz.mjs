// WP2 — Independent owner authorization (Ed25519 signed statements).
// The owner signing key lives only in the owner authorizer (bin/safebox-owner.mjs).
// The SafeBox service and executor hold only the owner's PUBLIC key, pinned in trusted config.
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { closeSync, fstatSync, openSync, readSync, writeFileSync, constants as C } from 'node:fs';
import { baseDecode, baseEncode } from 'near-api-js';
import {
  DOMAINS, fail, requireExactFields, canonicalJson, parseCanonical, domainBytes,
  isoMillis, simpleId, uuidV4, hex, atomicAmount, testnetAccountId,
} from './canonical.mjs';

export const AUTHZ_VERSION = 'safebox.authz.v1';
export const REVOKE_VERSION = 'safebox.revoke.v1';
export const MANDATE_VERSION = 'safebox.mandate.v1';
export const MAX_AUTHZ_TTL_MS = 15 * 60_000;
export const CLOCK_SKEW_MS = 60_000;

// ---- key handling -------------------------------------------------------
export function ownerKeyId(rawPub32) {
  if (!(rawPub32 instanceof Uint8Array) || rawPub32.length !== 32) fail('INVALID_PUBLIC_KEY');
  return 'ed25519:' + baseEncode(rawPub32);
}

export function rawFromKeyId(keyId) {
  if (typeof keyId !== 'string' || !/^ed25519:[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(keyId)) fail('INVALID_PUBLIC_KEY');
  const raw = baseDecode(keyId.slice(8));
  if (raw.length !== 32) fail('INVALID_PUBLIC_KEY');
  return raw;
}

function publicKeyObject(keyId) {
  const x = Buffer.from(rawFromKeyId(keyId)).toString('base64url');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
}

export function generateOwnerKey(principalId) {
  simpleId(principalId, 'principalId');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  return {
    file: { v: 'safebox.ownerkey.v1', principalId, publicKey: ownerKeyId(raw),
      privateKeyPkcs8: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64') },
    publicKey: ownerKeyId(raw),
  };
}

export function writeOwnerKeyFile(path, principalId) {
  const k = generateOwnerKey(principalId);
  writeFileSync(path, JSON.stringify(k.file, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return k.publicKey;
}

function readRestrictedFile(path, code) {
  let fd;
  try { fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW); }
  catch (e) {
    if (e.code === 'ELOOP') fail(code + '_SYMLINK');
    throw e;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) fail(code + '_NOT_A_FILE');
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) fail(code + '_TOO_PERMISSIVE', 'chmod 600 required');
    if (st.size > (1 << 20)) fail(code + '_TOO_LARGE');
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, null);
      if (n === 0) break;
      off += n;
    }
    if (off !== buf.length) fail(code + '_SHORT_READ');
    return buf.toString('utf8');
  } finally { closeSync(fd); }
}

// Opaque owner signer: the private key never leaves this closure.
export function loadOwnerSigner(path) {
  const f = JSON.parse(readRestrictedFile(path, 'OWNER_KEY_FILE'));
  requireExactFields(f, ['v', 'principalId', 'publicKey', 'privateKeyPkcs8'], 'INVALID_OWNER_KEY_FILE');
  const pk = createPrivateKey({ key: Buffer.from(f.privateKeyPkcs8, 'base64'), format: 'der', type: 'pkcs8' });
  const derivedRaw = Buffer.from(createPublicKey(pk).export({ format: 'jwk' }).x, 'base64url');
  if (ownerKeyId(derivedRaw) !== f.publicKey) fail('OWNER_KEY_MISMATCH');
  return makeSigner(f.principalId, f.publicKey, pk);
}

export function ownerSignerFromKeyObject(principalId, keyObject) { // tests / in-memory
  const raw = Buffer.from(createPublicKey(keyObject).export({ format: 'jwk' }).x, 'base64url');
  return makeSigner(principalId, ownerKeyId(raw), keyObject);
}

function makeSigner(principalId, publicKey, pk) {
  return Object.freeze({
    principalId, publicKey,
    signStatement(domain, statement) {
      const canonical = canonicalJson(statement);
      const signature = sign(null, domainBytes(domain, canonical), pk).toString('base64');
      return { statement: canonical, signature };
    },
    toJSON() { return { principalId, publicKey }; }, // never serialises the private key
  });
}

export function verifyStatement(domain, canonical, signatureB64, ownerKey) {
  if (typeof signatureB64 !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signatureB64)) return false;
  const sig = Buffer.from(signatureB64, 'base64');
  if (sig.length !== 64) return false;
  try { return verify(null, domainBytes(domain, canonical), publicKeyObject(ownerKey), sig); }
  catch { return false; }
}

// ---- statements ---------------------------------------------------------
const AUTHZ_FIELDS = ['v', 'intentId', 'intentDigest', 'principalId', 'ownerKey', 'challenge', 'issuedAt', 'expiresAt'];

export function authorizationStatement({ sealed, challenge, ownerKey, now, ttlMs = 5 * 60_000 }) {
  const exp = Math.min(now + ttlMs, Date.parse(sealed.intent.expiresAt));
  return {
    v: AUTHZ_VERSION, intentId: sealed.intent.intentId, intentDigest: sealed.digest,
    principalId: sealed.intent.principalId, ownerKey, challenge,
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(exp).toISOString(),
  };
}

export function parseAuthorization(canonical) {
  const a = parseCanonical(canonical, 2048);
  requireExactFields(a, AUTHZ_FIELDS);
  if (a.v !== AUTHZ_VERSION) fail('UNSUPPORTED_VERSION');
  uuidV4(a.intentId); hex(a.intentDigest, 32, 'intentDigest'); simpleId(a.principalId, 'principalId');
  rawFromKeyId(a.ownerKey); hex(a.challenge, 32, 'challenge');
  isoMillis(a.issuedAt, 'issuedAt'); isoMillis(a.expiresAt, 'expiresAt');
  return a;
}

/**
 * Full verification of an owner authorization against a sealed intent.
 * trustedOwnerKey comes from pinned configuration, never from the request.
 */
export function verifyAuthorization({ sealed, authorization, signature, trustedOwnerKey, expectedChallenge, now }) {
  const a = parseAuthorization(authorization);
  if (!trustedOwnerKey) fail('UNKNOWN_PRINCIPAL');
  if (a.principalId !== sealed.intent.principalId) fail('AUTHZ_PRINCIPAL_MISMATCH');
  if (a.ownerKey !== trustedOwnerKey) fail('AUTHZ_KEY_NOT_TRUSTED');
  if (a.intentId !== sealed.intent.intentId) fail('AUTHZ_INTENT_MISMATCH');
  if (a.intentDigest !== sealed.digest) fail('AUTHZ_DIGEST_MISMATCH');
  if (expectedChallenge !== undefined && a.challenge !== expectedChallenge) fail('AUTHZ_CHALLENGE_MISMATCH');
  if (!verifyStatement(DOMAINS.AUTHZ, authorization, signature, trustedOwnerKey)) fail('AUTHZ_BAD_SIGNATURE');
  const issued = Date.parse(a.issuedAt), exp = Date.parse(a.expiresAt);
  if (issued > now + CLOCK_SKEW_MS) fail('AUTHZ_FROM_FUTURE');
  if (exp <= issued || exp - issued > MAX_AUTHZ_TTL_MS) fail('AUTHZ_BAD_WINDOW');
  if (exp > Date.parse(sealed.intent.expiresAt)) fail('AUTHZ_OUTLIVES_INTENT');
  if (now >= exp) fail('AUTHZ_EXPIRED');
  return a;
}

const REVOKE_FIELDS = ['v', 'intentId', 'intentDigest', 'principalId', 'ownerKey', 'issuedAt'];
export function revocationStatement({ sealed, ownerKey, now }) {
  return { v: REVOKE_VERSION, intentId: sealed.intent.intentId, intentDigest: sealed.digest,
    principalId: sealed.intent.principalId, ownerKey, issuedAt: new Date(now).toISOString() };
}
export function verifyRevocation({ sealed, revocation, signature, trustedOwnerKey }) {
  const r = parseCanonical(revocation, 2048);
  requireExactFields(r, REVOKE_FIELDS);
  if (r.v !== REVOKE_VERSION || r.intentId !== sealed.intent.intentId || r.intentDigest !== sealed.digest ||
      r.principalId !== sealed.intent.principalId || r.ownerKey !== trustedOwnerKey) fail('REVOCATION_MISMATCH');
  if (!verifyStatement(DOMAINS.REVOKE, revocation, signature, trustedOwnerKey)) fail('REVOCATION_BAD_SIGNATURE');
  return r;
}

// Spending mandate: an owner-signed ceiling. It never replaces per-intent authorization.
const MANDATE_FIELDS = ['v', 'mandateId', 'principalId', 'ownerKey', 'action', 'maxPerIntentYocto',
  'maxTotalYocto', 'allowedRecipients', 'validFrom', 'expiresAt'];
export function parseMandate(canonical) {
  const m = parseCanonical(canonical, 8192);
  requireExactFields(m, MANDATE_FIELDS);
  if (m.v !== MANDATE_VERSION) fail('UNSUPPORTED_VERSION');
  simpleId(m.mandateId, 'mandateId'); simpleId(m.principalId, 'principalId'); rawFromKeyId(m.ownerKey);
  if (!['NEAR_NATIVE_TRANSFER', 'SAFEBOX_CONTRACT_PAYMENT'].includes(m.action)) fail('UNSUPPORTED_ACTION');
  atomicAmount(m.maxPerIntentYocto, 'maxPerIntentYocto'); atomicAmount(m.maxTotalYocto, 'maxTotalYocto');
  if (BigInt(m.maxPerIntentYocto) > BigInt(m.maxTotalYocto)) fail('MANDATE_INCONSISTENT');
  if (!Array.isArray(m.allowedRecipients) || m.allowedRecipients.length < 1 || m.allowedRecipients.length > 64) fail('MANDATE_RECIPIENTS');
  m.allowedRecipients.forEach(r => testnetAccountId(r, 'allowedRecipients'));
  if (new Set(m.allowedRecipients).size !== m.allowedRecipients.length) fail('MANDATE_RECIPIENTS');
  isoMillis(m.validFrom, 'validFrom'); isoMillis(m.expiresAt, 'expiresAt');
  if (Date.parse(m.expiresAt) <= Date.parse(m.validFrom)) fail('MANDATE_WINDOW');
  return m;
}
export function verifyMandate({ mandate, signature, trustedOwnerKey }) {
  const m = parseMandate(mandate);
  if (m.ownerKey !== trustedOwnerKey) fail('MANDATE_KEY_NOT_TRUSTED');
  if (!verifyStatement(DOMAINS.MANDATE, mandate, signature, trustedOwnerKey)) fail('MANDATE_BAD_SIGNATURE');
  return m;
}
