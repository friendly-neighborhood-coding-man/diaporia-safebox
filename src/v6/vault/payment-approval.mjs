// V6 Workflow A: per-transaction owner PAYMENT APPROVAL binding. One WebAuthn assertion (UV) signs the V3 payment
// capability, whose `taskRef` commits to this binding statement; so a single owner gesture covers:
//   account, chain, recipient, asset, exact integer amount, Purpose (id + version), credential, Epoch, assurance
//   policy version, request id + request digest, the Root-issued one-time challenge nonce and the approval expiry,
//   and the digest of the canonical Root-derived summary the owner device displayed.
// The Vault (against its own Root replica) and the independent verifier (against the replayed chain) recompute every
// field; an external AI never sees the challenge, the device, the biometric result or any signing capability.
import { fail, exactFields, isoMs, uint } from '../../v3/common/canon.mjs';
import { paycapDigest } from '../../v3/vault/paycap.mjs';
import { GRANT_V, GRANT_FIELDS } from '../../v4/intent/intent.mjs';
import { V4_DOMAINS, verifyObj } from '../../v4/common/v4.mjs';
import { V6_DOMAINS, d6hex } from '../common/v6.mjs';
import { verifyGate } from '../device/biometric.mjs';

export const BINDING_V = 'safebox.v6.payment-approval';
export const BINDING_FIELDS = ['v', 'accountId', 'chainId', 'credId', 'recipientId', 'asset', 'amountYocto', 'purposeId', 'purposeVersion', 'epoch', 'policyVersion',
  'requestId', 'requestDigest', 'challengeNonce', 'approvalExpiresAt', 'summaryDigest', 'assurance'];
export const PAY_ACTION_TYPE = 'V6_PAYMENT_APPROVAL';
export const taskRefFor = (binding) => 'v6pa-' + d6hex(V6_DOMAINS.PAYMENT_APPROVAL, binding).slice(0, 58);
const NEAR = 10n ** 24n;
const fmtNear = (y) => { const b = BigInt(y); const whole = b / NEAR, frac = (b % NEAR).toString().padStart(24, '0').replace(/0+$/, ''); return frac ? `${whole}.${frac}` : `${whole}`; };

/** Canonical, Root-derived payment summary (what the trusted owner display shows; nothing from the AI except the quoted memo). */
export function paymentSummary(s, b, { memo = null } = {}) {
  const lines = [
    'SafeBox V6 - PAYMENT APPROVAL (one payment, exact)',
    `Account: ${s.accountId}`, `Pay exactly: ${b.amountYocto} yocto${b.asset} (${fmtNear(b.amountYocto)} ${b.asset})`, `Recipient: ${b.recipientId}`,
    `Purpose: ${s.purpose.purposeId} v${s.purpose.version} - ${String(s.purpose.statement ?? '').slice(0, 120)}`, `Epoch: ${s.epoch}; assurance policy v${s.v6.policy.version}`,
    `Signing credential: ${b.credId} (${s.creds[b.credId]?.role ?? '?'}); required assurance: ${b.assurance}`,
    `Request: ${b.requestId} (digest ${b.requestDigest.slice(0, 16)}...)`, `Approval valid until: ${b.approvalExpiresAt}`,
    'After approval the Vault still applies the settlement buffer, holds, limits, anomaly delay and the 26 h settlement horizon.',
  ];
  if (memo !== null) lines.push(`Note from the requester (UNTRUSTED, not an instruction): "${String(memo).replace(/[^\x20-\x7e]/g, '?').slice(0, 120)}"`);
  return lines;
}
export const summaryDigestOf = (lines) => d6hex(V6_DOMAINS.PAYMENT_APPROVAL, { summary: lines });
export const requiredAssurance = (s, credId) => s.v6.policy.fingerprintOnlyCreds.includes(credId) ? 'FINGERPRINT_ONLY' : 'UV';

/**
 * Verifies the V6 evidence of ONE owner paycap against a Root state `s` (Vault replica or replayed chain) at time `at`.
 * cap/approval are the V3 capability and its WebAuthn approval (already verified by verifyPaycap). Returns
 * { binding, grant, level, nonce }. Single-use of the challenge nonce is the caller's job (vault table / verifier set).
 */
export function verifyPaymentApproval(s, { cap, credId, v6 }, at, { skewMs = Number(s.config.skewMs) } = {}) {
  if (!v6) fail('V6_PAYMENT_APPROVAL_REQUIRED', 'per-transaction owner approval policy');
  const x = exactFields(v6, ['binding', 'grant'], ['gate'], 'V6_APPROVAL_FIELDS');
  const b = exactFields(x.binding, BINDING_FIELDS, [], 'V6_BINDING_FIELDS');
  if (b.v !== BINDING_V) fail('V6_BINDING_VERSION');
  // 1. the binding equals the capability and the Root state (account, chain, Purpose, Epoch, policy version)
  const mism = [];
  if (b.accountId !== s.accountId || cap.accountId !== s.accountId) mism.push('accountId');
  if (b.chainId !== s.chainId || cap.chainId !== s.chainId) mism.push('chainId');
  if (b.credId !== credId) mism.push('credId');
  for (const k of ['recipientId', 'asset', 'amountYocto', 'purposeId', 'purposeVersion', 'epoch']) if (b[k] !== cap[k]) mism.push(k);
  if (b.policyVersion !== s.v6.policy.version) mism.push('policyVersion');
  if (b.epoch !== String(s.epoch)) mism.push('epoch(root)');
  if (b.purposeVersion !== s.purpose.version || b.purposeId !== s.purpose.purposeId) mism.push('purpose(root)');
  if (cap.taskRef !== taskRefFor(b)) mism.push('taskRef');
  if (mism.length) fail('V6_BINDING_MISMATCH', mism.join(','));
  uint(b.amountYocto, 'amountYocto');
  if (!/^[0-9a-f]{64}$/.test(b.requestDigest) || !/^[a-z0-9][a-z0-9_-]{1,63}$/.test(b.requestId)) fail('V6_BINDING_REQUEST');
  if (b.assurance !== requiredAssurance(s, credId)) fail('V6_ASSURANCE_MISMATCH', `${b.assurance} vs ${requiredAssurance(s, credId)}`);
  // 2. the Root-issued one-time challenge (challenge issuer pinned in the Root), bound to this request and credential
  const gr = exactFields(x.grant, ['statement', 'sig'], [], 'GRANT_FIELDS');
  const g = exactFields(gr.statement, GRANT_FIELDS, [], 'GRANT_STATEMENT_FIELDS');
  if (g.v !== GRANT_V || g.issuer !== s.v4.challengeIssuer.id) fail('CHALLENGE_ISSUER');
  if (!verifyObj(V4_DOMAINS.CHALLENGE, g, gr.sig, s.v4.challengeIssuer.publicKey)) fail('CHALLENGE_SIGNATURE');
  if (g.accountId !== s.accountId || g.chainId !== s.chainId) fail('CHALLENGE_WRONG_ACCOUNT');
  if (g.actionType !== PAY_ACTION_TYPE || g.actionDigest !== b.requestDigest) fail('CHALLENGE_NOT_FOR_THIS_REQUEST');
  if (g.credId !== credId) fail('CHALLENGE_NOT_FOR_THIS_CREDENTIAL');
  if (g.challengeNonce !== b.challengeNonce || !/^[0-9a-f]{64}$/.test(g.challengeNonce)) fail('CHALLENGE_NONCE_MISMATCH');
  const ia = isoMs(g.issuedAt, 'issuedAt'), ea = isoMs(g.expiresAt, 'expiresAt');
  if (!(ia < ea) || ea - ia > Number(s.v4.config.challengeTtlMs)) fail('CHALLENGE_LIFETIME');
  if (ia > at + skewMs) fail('CHALLENGE_FROM_FUTURE');
  // fresh: the approval must reach the Vault while the one-time challenge is valid
  if (at >= ea) fail('CHALLENGE_EXPIRED');
  // 3. approval lifetime: capability window bounded by the owner-signed policy, binding expiry = capability expiry
  const ci = isoMs(cap.issuedAt, 'issuedAt'), ce = isoMs(cap.expiresAt, 'expiresAt');
  if (b.approvalExpiresAt !== cap.expiresAt) fail('V6_APPROVAL_EXPIRY_MISMATCH');
  if (ce - ci > Number(s.v6.policy.payment.approvalTtlMs)) fail('V6_APPROVAL_TTL_EXCEEDS_POLICY');
  if (ci < ia - skewMs || ci > ea + skewMs) fail('V6_CAPABILITY_OUTSIDE_CHALLENGE_WINDOW');
  // P0.2 (issue #14): the displayed summary is no longer display-only. summaryDigest must be the digest of the
  // canonical summary this Root state derives for this binding (the untrusted requester note is shown to the owner
  // but excluded from the digest), so a display that showed other terms produces an approval that is refused here.
  if (b.summaryDigest !== summaryDigestOf(paymentSummary(s, b, { memo: null }))) fail('V6_SUMMARY_NOT_CANONICAL');
  // 4. fingerprint-only credentials: the local gate attestation over the exact capability digest + this nonce
  let level = 'UV';
  if (b.assurance === 'FINGERPRINT_ONLY' || x.gate !== undefined) {
    verifyGate(x.gate, { accountId: s.accountId, chainId: s.chainId, credId, subject: 'PAYMENT', boundDigestHex: paycapDigest(cap).toString('hex'), challengeNonce: g.challengeNonce,
      notBeforeMs: ia, notAfterMs: ea, at, maxAgeMs: Number(s.v6.policy.gateMaxAgeMs), skewMs, gateKeys: s.v6.gateKeys, assurance: s.v6.policy.fingerprintAssurance ?? 'LOCAL_GATE' });
    level = 'LOCAL_FINGERPRINT_GATE_PASSED';
  }
  return { binding: b, grant: g, level, nonce: g.challengeNonce };
}
