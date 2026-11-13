// SafeBox V3 canonical encoding and signing primitives.
// One textual form per value: plain objects (sorted keys), arrays and printable-ASCII strings only — no numbers,
// booleans or nulls, so there is never a second spelling of the same statement. Domain separation is mandatory and
// every V3 domain is distinct from every V1/V2 domain, so no V3 signature can verify as an older statement.
import { createHash, createPublicKey, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { SafeBoxError, isPlainObject } from '../../v1/canonical.mjs';

export { SafeBoxError };
export const fail = (code, detail) => { throw new SafeBoxError(code, detail); };

export const V3_DOMAINS = Object.freeze({
  ACTION: 'DIAPORIA_SAFEBOX_V3_AUTHORITY_ACTION\n',      // governance / rotation / recovery actions (approved by credentials)
  PAYCAP: 'DIAPORIA_SAFEBOX_V3_PAYMENT_CAPABILITY\n',    // K1/K2 payment capabilities
  CAPSULE: 'DIAPORIA_SAFEBOX_V3_PURPOSE_CAPSULE\n',      // purpose capsule digest domain
  MATRIX: 'DIAPORIA_SAFEBOX_V3_AUTHORITY_MATRIX\n',
  TRANSITION: 'DIAPORIA_SAFEBOX_V3_ROOT_TRANSITION\n',   // hash chain of root transitions
  GUARDIAN: 'DIAPORIA_SAFEBOX_V3_GUARDIAN_APPROVAL\n',
  IDENTITY: 'DIAPORIA_SAFEBOX_V3_IDENTITY_ATTESTATION\n',
  OFFICIAL: 'DIAPORIA_SAFEBOX_V3_OFFICIAL_DOCUMENT\n',
  CHANNEL: 'DIAPORIA_SAFEBOX_V3_NOTIFICATION_CHANNEL\n',
  DISPATCH: 'DIAPORIA_SAFEBOX_V3_NOTIFICATION_DISPATCH\n',
  REPAIR: 'DIAPORIA_SAFEBOX_V3_REPAIR_CERTIFICATE\n',
  SUPERVISOR_FREEZE: 'DIAPORIA_SAFEBOX_V3_SUPERVISOR_FREEZE\n',
  ENROLL: 'DIAPORIA_SAFEBOX_V3_ENROLLMENT_POP\n',
  LEDGER_TX: 'DIAPORIA_SAFEBOX_V3_LEDGER_TX\n',
});
const DOMAIN_SET = new Set(Object.values(V3_DOMAINS));

const SAFE_TEXT = /^[\x20-\x7e]*$/;
const KEY_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
export const MAX_DEPTH = 10;

export function canon(v, depth = 0) {
  if (depth > MAX_DEPTH) fail('CANONICAL_TOO_DEEP');
  if (typeof v === 'string') { if (!SAFE_TEXT.test(v)) fail('CANONICAL_NON_ASCII'); return JSON.stringify(v); }
  if (Array.isArray(v)) { if (v.length > 256) fail('CANONICAL_ARRAY_TOO_LONG'); return '[' + v.map(x => canon(x, depth + 1)).join(',') + ']'; }
  if (isPlainObject(v)) {
    if (Object.getOwnPropertySymbols(v).length) fail('CANONICAL_SYMBOL_KEY');
    const keys = Object.keys(v).sort();
    if (keys.length > 64) fail('CANONICAL_TOO_MANY_KEYS');
    return '{' + keys.map(k => { if (!KEY_RE.test(k)) fail('CANONICAL_BAD_KEY', k); return JSON.stringify(k) + ':' + canon(v[k], depth + 1); }).join(',') + '}';
  }
  fail('CANONICAL_BAD_VALUE_TYPE', typeof v);
}

export function parseCanon(text, maxBytes = 65536) {
  if (typeof text !== 'string') fail('CANONICAL_NOT_STRING');
  if (Buffer.byteLength(text) > maxBytes) fail('INPUT_TOO_LARGE');
  let o; try { o = JSON.parse(text); } catch { fail('CANONICAL_PARSE_ERROR'); }
  if (canon(o) !== text) fail('NOT_CANONICAL');
  return o;
}

export const sha256 = (buf) => createHash('sha256').update(buf).digest();
export const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');
export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64u = (s, field = 'b64u') => { if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) fail('BAD_BASE64URL', field); return Buffer.from(s, 'base64url'); };

export function domainBytes(domain, obj) {
  if (!DOMAIN_SET.has(domain)) fail('UNKNOWN_DOMAIN');
  return Buffer.concat([Buffer.from(domain), Buffer.from(typeof obj === 'string' ? obj : canon(obj))]);
}
/** Digest that every signer approves: sha256(domain || canonical(statement)). */
export const digest = (domain, obj) => sha256(domainBytes(domain, obj));
export const digestHex = (domain, obj) => digest(domain, obj).toString('hex');

// ---------- Ed25519 external signing credentials (hardware-wallet style) ----------
export const ED_PREFIX = 'ed25519:';
export function edPublicId(publicKeyObject) { return ED_PREFIX + b64u(Buffer.from(createPublicKey(publicKeyObject).export({ format: 'jwk' }).x, 'base64url')); }
function edKeyObject(pubId) {
  if (typeof pubId !== 'string' || !pubId.startsWith(ED_PREFIX)) fail('BAD_PUBLIC_KEY');
  const raw = fromB64u(pubId.slice(ED_PREFIX.length));
  if (raw.length !== 32) fail('BAD_PUBLIC_KEY');
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64u(raw) }, format: 'jwk' });
}
/** Opaque signer: the private key never leaves the closure. Signs the 32-byte action digest under a domain. */
export function newEdSigner(label = 'ed25519') {
  const { privateKey } = generateKeyPairSync('ed25519');
  const publicKey = edPublicId(privateKey);
  return Object.freeze({
    label, kind: 'ed25519', publicKey,
    signDigest(domain, dig) { return b64u(sign(null, Buffer.concat([Buffer.from(domain), Buffer.from(dig)]), privateKey)); },
    signStatement(domain, obj) { return b64u(sign(null, domainBytes(domain, obj), privateKey)); },
    toJSON() { return { label, kind: 'ed25519', publicKey }; },
  });
}
export function edVerifyDigest(domain, dig, sigB64u, pubId) {
  try { const s = fromB64u(sigB64u); if (s.length !== 64) return false; return verify(null, Buffer.concat([Buffer.from(domain), Buffer.from(dig)]), edKeyObject(pubId), s); } catch { return false; }
}
export function edVerifyStatement(domain, obj, sigB64u, pubId) {
  try { const s = fromB64u(sigB64u); if (s.length !== 64) return false; return verify(null, domainBytes(domain, obj), edKeyObject(pubId), s); } catch { return false; }
}

export const nonce = () => randomBytes(16).toString('hex');
export const iso = (ms) => new Date(ms).toISOString();
export function isoMs(v, field) {
  if (typeof v !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v) || new Date(v).toISOString() !== v) fail('INVALID_TIMESTAMP', field);
  return Date.parse(v);
}
export const ID_RE = /^[a-z0-9][a-z0-9_-]{1,63}$/;
export function id(v, field) { if (typeof v !== 'string' || !ID_RE.test(v)) fail('INVALID_ID', field); return v; }
export function uint(v, field, max = 10n ** 30n) { if (typeof v !== 'string' || !/^(0|[1-9][0-9]{0,38})$/.test(v) || BigInt(v) > max) fail('INVALID_UINT', field); return BigInt(v); }
export function exactFields(o, req, opt = [], code = 'UNEXPECTED_OR_MISSING_FIELD') {
  if (!isPlainObject(o)) fail('INVALID_OBJECT', code);
  const keys = Object.keys(o);
  const extra = keys.filter(k => !req.includes(k) && !opt.includes(k));
  const missing = req.filter(k => !Object.prototype.hasOwnProperty.call(o, k));
  if (extra.length || missing.length) fail(code, `${extra.length ? 'unknown=' + extra.slice(0, 4).join(',') : ''}${missing.length ? ' missing=' + missing.slice(0, 4).join(',') : ''}`.trim());
  return o;
}
export const deepFreeze = (o) => { if (o && typeof o === 'object') { Object.values(o).forEach(deepFreeze); Object.freeze(o); } return o; };
export const clone = (o) => JSON.parse(JSON.stringify(o));
