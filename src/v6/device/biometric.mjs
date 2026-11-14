// V6 biometric gate: a LOCAL fingerprint verification (Windows Biometric Framework, WinBioVerify) that, only on a
// match, has an enrolled gate key sign the EXACT digest being approved plus the Root-issued one-time challenge nonce.
//
// Trust boundary (stated, not hidden):
//  * The gate key sits on the owner's laptop (TPM-backed CNG key when available, else a software key). Its signature
//    proves "the gate helper running on the enrolled laptop observed a WinBio fingerprint MATCH for the current Windows
//    user and then signed this digest". It is NOT a hardware attestation that a fingerprint, rather than a PIN, unlocked
//    a key: a compromised OS or helper could sign without a finger. We label a pass LOCAL_FINGERPRINT_GATE_PASSED /
//    FINGERPRINT_ONLY_LOCALLY_VERIFIED, never CRYPTOGRAPHICALLY_ATTESTED_FINGERPRINT_ONLY.
//  * The WebAuthn assertion (Windows Hello UV) is still required next to the gate; UV alone may be a PIN.
//  * No biometric sample, template, score or WinBio session ever leaves the helper; SafeBox receives only the signed
//    statement {method, result:MATCH, digest, nonce, time}. A caller-supplied boolean is never accepted.
import { fail, exactFields, isoMs, iso } from '../../v3/common/canon.mjs';
import { V6_DOMAINS, GATE_METHOD, verifyEs256Obj, newGateKey } from '../common/v6.mjs';

export const GATE_V = 'safebox.v6.biometric-gate';
export const GATE_FIELDS = ['v', 'accountId', 'chainId', 'credId', 'gateKeyId', 'method', 'result', 'subject', 'boundDigest', 'challengeNonce', 'verifiedAt', 'sensorClass'];
export const GATE_SUBJECTS = Object.freeze(['COMMAND', 'PAYMENT']);

/**
 * P0.1 (issue #14): gate key kinds whose signing is isolated from code running as the owner's OS user (an independent
 * signer with its own display and an on-device biometric match bound to key use). EMPTY in V6: SIMULATED, WINBIO_TPM
 * and WINBIO_SOFTWARE_KEY are per-user CNG/software keys with no UI policy, so same-user code can sign with them.
 */
export const ISOLATED_GATE_KINDS = Object.freeze([]);
export const highAssuranceGate = (k) => ISOLATED_GATE_KINDS.includes(k?.kind);
export const gateKeyProtection = (k) => (highAssuranceGate(k) ? 'ISOLATED_SIGNER' : 'SAME_USER_KEY');
/** Outcomes a fingerprint attempt can have on the device. Only MATCH produces a gate attestation. */
export const BIO_OUTCOMES = Object.freeze({ MATCH: 'MATCH', NO_MATCH: 'NO_MATCH', PIN_ONLY: 'PIN_ONLY', LOCKOUT: 'LOCKOUT', TIMEOUT: 'TIMEOUT', UNSUPPORTED: 'UNSUPPORTED', CANCELLED: 'CANCELLED' });
const OUTCOME_CODE = { NO_MATCH: 'BIOMETRIC_NO_MATCH', PIN_ONLY: 'BIOMETRIC_PIN_NOT_ACCEPTED', LOCKOUT: 'BIOMETRIC_LOCKOUT', TIMEOUT: 'BIOMETRIC_TIMEOUT', UNSUPPORTED: 'FINGERPRINT_ONLY_UNSUPPORTED', CANCELLED: 'BIOMETRIC_CANCELLED' };

/**
 * Root/Vault-side verification of ONE gate attestation. `gateKeys`: credId -> {gateKeyId, spki, sensorClass} from the
 * replayed owner-signed V6 genesis. Window: [notBefore - skew, notAfter] (the challenge grant window) and max age.
 */
export function verifyGate(gate, { accountId, chainId, credId, subject, boundDigestHex, challengeNonce, notBeforeMs, notAfterMs, at, maxAgeMs, skewMs = 30_000, gateKeys, assurance = 'LOCAL_GATE' }) {
  const k = gateKeys[credId];
  if (!k) fail('FINGERPRINT_ONLY_UNSUPPORTED', `no gate key enrolled for ${credId}`);
  // P0.1: a same-user gate key cannot prove a finger against same-user code; HIGH_ASSURANCE refuses it outright
  if (assurance !== 'LOCAL_GATE' && !highAssuranceGate(k)) fail('FINGERPRINT_ONLY_HIGH_ASSURANCE_UNAVAILABLE', `${credId}: gate key ${k.kind} is usable by same-user code without a finger`);
  if (!gate) fail('FINGERPRINT_GATE_REQUIRED', credId);
  const x = exactFields(gate, ['statement', 'sig'], [], 'GATE_FIELDS');
  const st = exactFields(x.statement, GATE_FIELDS, [], 'GATE_STATEMENT_FIELDS');
  if (st.v !== GATE_V) fail('GATE_VERSION');
  if (st.accountId !== accountId || st.chainId !== chainId) fail('GATE_WRONG_ACCOUNT');
  if (st.credId !== credId || st.gateKeyId !== k.gateKeyId) fail('GATE_WRONG_CREDENTIAL');
  if (st.method !== GATE_METHOD) fail('GATE_METHOD_NOT_FINGERPRINT', String(st.method));
  if (st.result !== 'MATCH') fail('GATE_RESULT_NOT_MATCH', String(st.result));
  if (st.subject !== subject) fail('GATE_WRONG_SUBJECT');
  if (st.boundDigest !== boundDigestHex) fail('GATE_NOT_FOR_THIS_DIGEST');
  if (st.challengeNonce !== challengeNonce) fail('GATE_NOT_FOR_THIS_CHALLENGE');
  if (!verifyEs256Obj(V6_DOMAINS.BIOMETRIC_GATE, st, x.sig, k.spki)) fail('GATE_BAD_SIGNATURE');
  const t = isoMs(st.verifiedAt, 'verifiedAt');
  if (t < notBeforeMs - skewMs || t > notAfterMs + skewMs) fail('GATE_OUTSIDE_CHALLENGE_WINDOW');
  if (t > at + skewMs) fail('GATE_FROM_FUTURE');
  if (at - t > maxAgeMs) fail('GATE_STALE');
  return { level: 'LOCAL_FINGERPRINT_GATE_PASSED', verifiedAt: t };
}

/**
 * SIMULATED fingerprint device (tests and the mock showcase; labelled SIMULATED DEVICE). The scripted `next` outcome
 * models what the physical sensor would report; only MATCH makes the enrolled gate key sign. There is no code path that
 * turns NO_MATCH / PIN_ONLY / LOCKOUT / TIMEOUT / UNSUPPORTED into a gate: they throw, and the caller fails closed.
 */
export class SimulatedFingerprintGate {
  constructor({ credId, gateKeyId = 'gate-' + credId, sensorClass = 'SIMULATED_SENSOR', supported = true } = {}) {
    this.credId = credId; this.gateKeyId = gateKeyId; this.sensorClass = sensorClass; this.supported = supported;
    this.key = newGateKey(gateKeyId); this.queue = []; this.log = []; this.kind = 'SIMULATED';
  }
  /** Enrollment record for the V6 genesis (with proof of possession bound to account / V5 chain / credential). */
  enrollment({ accountId, v5ChainId }) {
    return { gateKeyId: this.gateKeyId, spki: this.key.spki, sensorClass: this.sensorClass, kind: 'SIMULATED',
      pop: this.key.signObj(V6_DOMAINS.GATE_POP, { accountId, v5ChainId, credId: this.credId, gateKeyId: this.gateKeyId }) };
  }
  /** Script the next physical outcome(s). */
  next(...outcomes) { this.queue.push(...outcomes); return this; }
  attest({ accountId, chainId, subject, boundDigestHex, challengeNonce, at }) {
    const outcome = !this.supported ? BIO_OUTCOMES.UNSUPPORTED : (this.queue.shift() ?? BIO_OUTCOMES.MATCH);
    this.log.push({ at, outcome, subject });
    if (outcome !== BIO_OUTCOMES.MATCH) fail(OUTCOME_CODE[outcome] ?? 'BIOMETRIC_FAILED', outcome);
    const statement = { v: GATE_V, accountId, chainId, credId: this.credId, gateKeyId: this.gateKeyId, method: GATE_METHOD, result: 'MATCH', subject,
      boundDigest: boundDigestHex, challengeNonce, verifiedAt: iso(at), sensorClass: this.sensorClass };
    return { statement, sig: this.key.signObj(V6_DOMAINS.BIOMETRIC_GATE, statement) };
  }
}
export { OUTCOME_CODE };
