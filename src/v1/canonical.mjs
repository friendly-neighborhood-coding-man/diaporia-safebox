// Deterministic, domain-separated canonical encoding for SafeBox V1.
// Values are restricted to strings and arrays of strings so that there is
// exactly one textual form per object (no numbers, no floats, no nulls).
import { createHash } from 'node:crypto';

export class SafeBoxError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.code = code;
  }
}
export const fail = (code, detail) => { throw new SafeBoxError(code, detail); };

export const DOMAINS = Object.freeze({
  INTENT: 'DIAPORIA_SAFEBOX_INTENT_V1\n',
  AUTHZ: 'DIAPORIA_SAFEBOX_AUTHZ_V1\n',
  REVOKE: 'DIAPORIA_SAFEBOX_REVOKE_V1\n',
  MANDATE: 'DIAPORIA_SAFEBOX_MANDATE_V1\n',
});

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

export function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// Exact field set check: no unknown, no missing, no inherited, no symbol keys.
export function requireExactFields(obj, fields, code = 'UNEXPECTED_OR_MISSING_FIELD') {
  if (!isPlainObject(obj)) fail('INVALID_OBJECT');
  if (Object.getOwnPropertySymbols(obj).length) fail(code, 'symbol key');
  const keys = Object.keys(obj);
  const extra = keys.filter(k => !fields.includes(k));
  const missing = fields.filter(k => !own(obj, k));
  if (extra.length || missing.length) {
    fail(code, [extra.length ? `unknown=${extra.slice(0, 5).join(',')}` : '', missing.length ? `missing=${missing.join(',')}` : ''].filter(Boolean).join(' '));
  }
}

// Printable ASCII only: removes homoglyph/normalisation/escape ambiguity.
const SAFE_TEXT = /^[\x20-\x7e]*$/;

export function canonicalJson(obj) {
  if (!isPlainObject(obj)) fail('CANONICAL_NOT_OBJECT');
  const keys = Object.keys(obj).sort();
  const parts = keys.map(k => {
    if (!/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(k)) fail('CANONICAL_BAD_KEY', k);
    const v = obj[k];
    let enc;
    if (typeof v === 'string') {
      if (!SAFE_TEXT.test(v)) fail('CANONICAL_NON_ASCII', k);
      enc = JSON.stringify(v);
    } else if (Array.isArray(v)) {
      if (!v.every(x => typeof x === 'string' && SAFE_TEXT.test(x))) fail('CANONICAL_BAD_ARRAY', k);
      enc = '[' + v.map(x => JSON.stringify(x)).join(',') + ']';
    } else {
      fail('CANONICAL_BAD_VALUE_TYPE', k);
    }
    return JSON.stringify(k) + ':' + enc;
  });
  return '{' + parts.join(',') + '}';
}

export function domainBytes(domain, canonical) {
  if (!Object.values(DOMAINS).includes(domain)) fail('UNKNOWN_DOMAIN');
  return Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from(canonical, 'utf8')]);
}

export function domainDigestHex(domain, canonical) {
  return createHash('sha256').update(domainBytes(domain, canonical)).digest('hex');
}

// Strict parse of a canonical JSON string: must round-trip byte-for-byte.
export function parseCanonical(text, maxBytes = 8192) {
  if (typeof text !== 'string') fail('CANONICAL_NOT_STRING');
  if (Buffer.byteLength(text, 'utf8') > maxBytes) fail('INPUT_TOO_LARGE');
  let obj;
  try { obj = JSON.parse(text); } catch { fail('CANONICAL_PARSE_ERROR'); }
  if (canonicalJson(obj) !== text) fail('NOT_CANONICAL');
  return obj;
}

// ---- field validators -------------------------------------------------
export const U128_MAX = (1n << 128n) - 1n;

export function atomicAmount(v, field = 'amount', { allowZero = false } = {}) {
  if (typeof v !== 'string') fail('INVALID_AMOUNT', `${field} must be a decimal string`);
  const re = allowZero ? /^(0|[1-9][0-9]{0,38})$/ : /^[1-9][0-9]{0,38}$/;
  if (!re.test(v)) fail('INVALID_AMOUNT', field);
  if (BigInt(v) > U128_MAX) fail('INVALID_AMOUNT', `${field} exceeds u128`);
  return v;
}

export function isoMillis(v, field) {
  if (typeof v !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v) ||
      !Number.isFinite(Date.parse(v)) || new Date(v).toISOString() !== v) fail('INVALID_TIMESTAMP', field);
  return v;
}

export const ID_RE = /^[a-z0-9][a-z0-9_-]{2,63}$/;
export function simpleId(v, field) {
  if (typeof v !== 'string' || !ID_RE.test(v)) fail('INVALID_ID', field);
  return v;
}

export function uuidV4(v, field = 'intentId') {
  if (typeof v !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v)) fail('INVALID_ID', field);
  return v;
}

export function hex(v, bytes, field) {
  if (typeof v !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(v)) fail('INVALID_HEX', field);
  return v;
}

// NEAR account id rules (nearcore AccountId) + SafeBox TESTNET-ONLY policy:
// named accounts must end in ".testnet"; 64-hex implicit accounts allowed.
const NEAR_ACCOUNT_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
export function testnetAccountId(v, field) {
  if (typeof v !== 'string' || v.length < 2 || v.length > 64 || !NEAR_ACCOUNT_RE.test(v)) fail('INVALID_ACCOUNT_ID', field);
  const implicit = /^[0-9a-f]{64}$/.test(v);
  if (!implicit && !(v.endsWith('.testnet') && v !== 'testnet')) fail('NOT_A_TESTNET_ACCOUNT', `${field}=${v}`);
  return v;
}

// yoctoNEAR -> human text without floating point.
export function formatYocto(yocto) {
  const v = BigInt(atomicAmount(yocto, 'amount', { allowZero: true }));
  const unit = 10n ** 24n;
  const whole = v / unit;
  const frac = (v % unit).toString().padStart(24, '0').replace(/0+$/, '');
  return `${whole}${frac ? '.' + frac : ''} NEAR`;
}
