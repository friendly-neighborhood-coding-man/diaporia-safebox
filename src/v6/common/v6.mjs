// SafeBox V6 (security closeout) primitives: domains, the owner-signed ASSURANCE POLICY, evidence labels.
// V6 adds no new cryptography: SHA-256 domain-separated digests over the V3 canonical encoding, Ed25519 (V5 signers)
// for service statements and ECDSA P-256 (ES256) for biometric-gate keys, both through node:crypto / OpenSSL.
import { createHash, createPublicKey, verify as cverify, generateKeyPairSync, sign as csign } from 'node:crypto';
import { canon, fail, exactFields, b64u, fromB64u } from '../../v3/common/canon.mjs';

export const PROTOCOL6 = 'safebox.v6';
export const V6_DOMAINS = Object.freeze({
  GENESIS: 'DIAPORIA_SAFEBOX_V6_GENESIS\n',
  GENESIS_EXT: 'DIAPORIA_SAFEBOX_V6_GENESIS_EXTENSION\n',
  PAYMENT_APPROVAL: 'DIAPORIA_SAFEBOX_V6_PAYMENT_APPROVAL\n',   // per-transaction owner approval binding (Workflow A)
  BIOMETRIC_GATE: 'DIAPORIA_SAFEBOX_V6_BIOMETRIC_GATE\n',       // local fingerprint-gate attestation (NOT hardware attestation)
  GATE_POP: 'DIAPORIA_SAFEBOX_V6_BIOMETRIC_GATE_POP\n',
  LOCATOR: 'DIAPORIA_SAFEBOX_V6_INCIDENT_LOCATOR\n',
  SESSION: 'DIAPORIA_SAFEBOX_V6_OWNER_SESSION\n',               // owner console login challenge (authorizes nothing)
  RECEIPT: 'DIAPORIA_SAFEBOX_V6_INBOX_RECEIPT\n',
});
const DSET = new Set(Object.values(V6_DOMAINS));
const dom = (d) => { if (!DSET.has(d)) fail('UNKNOWN_V6_DOMAIN'); return Buffer.from(d); };
export const d6 = (domain, obj) => createHash('sha256').update(Buffer.concat([dom(domain), Buffer.from(canon(obj))])).digest();
export const d6hex = (domain, obj) => d6(domain, obj).toString('hex');

/**
 * Assurance a credential's approvals must carry (owner-signed in the V6 genesis extension).
 *   UV                 WebAuthn user verification (Windows Hello: fingerprint, face OR PIN; the RP cannot tell which).
 *   FINGERPRINT_ONLY   UV AND a fresh local fingerprint-gate attestation bound to the exact approved digest, from a
 *                      gate key enrolled for that credential. A PIN cannot produce it. Fail closed if no gate key.
 */
export const ASSURANCE = Object.freeze({ UV: 'UV', FINGERPRINT_ONLY: 'FINGERPRINT_ONLY' });
/** Payment approval modes. */
export const PAYMENT_MODES = Object.freeze({
  LEGACY_V5: 'LEGACY_V5',                         // V5 behaviour: a UV paycap is enough (no V6 binding)
  PER_TRANSACTION: 'PER_TRANSACTION',             // every owner paycap needs a V6 binding + Root-issued one-time challenge
});
export const GATE_METHOD = 'WINBIO_FINGERPRINT';

/** Evidence classification labels (only labels backed by actual evidence may be displayed). */
export const LABELS = Object.freeze({
  MOCK_LEDGER: 'MOCK LEDGER', SIMULATED_DEVICE: 'SIMULATED DEVICE', REAL_GMAIL: 'REAL GMAIL', REAL_DEVICE_AUTH: 'REAL DEVICE AUTH',
  PIN_FALLBACK_POSSIBLE: 'PIN FALLBACK POSSIBLE', FINGERPRINT_ONLY_NOT_PROVEN: 'FINGERPRINT ONLY NOT PROVEN', NOT_RUN: 'NOT RUN',
});
/** Device-assurance results (mission section 2). */
export const DEVICE_RESULTS = Object.freeze({
  WINDOWS_HELLO_UV_VERIFIED: 'WINDOWS_HELLO_UV_VERIFIED',
  FINGERPRINT_ONLY_LOCALLY_VERIFIED: 'FINGERPRINT_ONLY_LOCALLY_VERIFIED',
  FINGERPRINT_ONLY_NOT_PROVEN: 'FINGERPRINT_ONLY_NOT_PROVEN',
  FINGERPRINT_ONLY_UNSUPPORTED: 'FINGERPRINT_ONLY_UNSUPPORTED',
});

export const DEFAULT_ASSURANCE_POLICY = Object.freeze({
  version: '1',
  payment: { mode: PAYMENT_MODES.PER_TRANSACTION, approvalTtlMs: String(5 * 60_000) },
  // credentials whose every approval (payments AND V5 commands) needs FINGERPRINT_ONLY; others need UV
  fingerprintOnlyCreds: [],
  // previously authorized bounded delegation stays a separate policy: delegated ops do not need a new fingerprint
  delegation: 'BOUNDED_DELEGATION_ALLOWED',
  gateMaxAgeMs: String(2 * 60_000),
  emergency: { origin: 'https://safebox.local', locatorTtlMs: String(72 * 3600_000) },
});

const POLICY_FIELDS = ['version', 'payment', 'fingerprintOnlyCreds', 'delegation', 'gateMaxAgeMs', 'emergency'];
export function parsePolicy(p) {
  exactFields(p, POLICY_FIELDS, [], 'V6_POLICY_FIELDS');
  if (!/^[1-9][0-9]{0,6}$/.test(p.version)) fail('V6_POLICY_VERSION');
  exactFields(p.payment, ['mode', 'approvalTtlMs'], [], 'V6_POLICY_PAYMENT');
  if (!Object.values(PAYMENT_MODES).includes(p.payment.mode)) fail('V6_POLICY_PAYMENT_MODE');
  const ttl = Number(p.payment.approvalTtlMs); if (!(ttl >= 30_000 && ttl <= 15 * 60_000)) fail('V6_POLICY_APPROVAL_TTL');
  if (!Array.isArray(p.fingerprintOnlyCreds) || p.fingerprintOnlyCreds.some(c => typeof c !== 'string')) fail('V6_POLICY_FP_CREDS');
  if (!['BOUNDED_DELEGATION_ALLOWED', 'DELEGATION_DISABLED'].includes(p.delegation)) fail('V6_POLICY_DELEGATION');
  const g = Number(p.gateMaxAgeMs); if (!(g >= 10_000 && g <= 10 * 60_000)) fail('V6_POLICY_GATE_AGE');
  exactFields(p.emergency, ['origin', 'locatorTtlMs'], [], 'V6_POLICY_EMERGENCY');
  if (!/^https:\/\/[a-z0-9.-]+(:[0-9]{2,5})?$/.test(p.emergency.origin) && !/^http:\/\/(localhost|127\.0\.0\.1)(:[0-9]{2,5})?$/.test(p.emergency.origin)) fail('V6_POLICY_EMERGENCY_ORIGIN');
  return JSON.parse(JSON.stringify(p));
}

// ------------------------------------------------------------------ ES256 gate keys
export function es256Spki(publicKey) { return b64u(publicKey.export({ format: 'der', type: 'spki' })); }
/** Software P-256 gate key (simulation, or a non-TPM fallback on a real device; labelled accordingly). */
export function newGateKey(label = 'gate') {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = es256Spki(publicKey);
  return Object.freeze({ label, spki, alg: 'ES256',
    signObj(domain, obj) { return b64u(csign('sha256', Buffer.concat([dom(domain), Buffer.from(canon(obj))]), { key: privateKey, dsaEncoding: 'ieee-p1363' })); },
    toJSON() { return { label, spki }; } });
}
/** Verifies an ES256 signature over (domain || canonical(obj)); accepts IEEE-P1363 (r||s, 64 bytes) or DER. */
export function verifyEs256Obj(domain, obj, sig, spki) {
  try {
    const key = createPublicKey({ key: fromB64u(spki), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return false;
    const raw = fromB64u(sig); const data = Buffer.concat([dom(domain), Buffer.from(canon(obj))]);
    return cverify('sha256', data, { key, dsaEncoding: raw.length === 64 ? 'ieee-p1363' : 'der' }, raw);
  } catch { return false; }
}
export { canon };
