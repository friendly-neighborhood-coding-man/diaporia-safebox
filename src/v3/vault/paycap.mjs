// K1/K2 payment capability: one owner-approved payment, bound to the Root epoch, matrix version and purpose version.
// The approval is a WebAuthn assertion (UV) whose challenge is the capability digest — it authorizes exactly this
// payment, never a session.
import { fail, exactFields, id, uint, isoMs, digest, V3_DOMAINS, edVerifyDigest } from '../common/canon.mjs';
import { verifyAssertion } from '../webauthn/verify.mjs';

export const PAYCAP_V = 'safebox.v3.paycap';
const FIELDS = ['v', 'capId', 'accountId', 'chainId', 'epoch', 'matrixVersion', 'purposeId', 'purposeVersion', 'operation', 'recipientId', 'asset', 'amountYocto', 'sku', 'taskRef', 'nonce', 'issuedAt', 'expiresAt'];
export const paycapDigest = (cap) => digest(V3_DOMAINS.PAYCAP, cap);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * Verifies a capability + its single approval against the vault's OWN replica of the Root state.
 * signCountFloor(credId) -> highest authenticator counter the vault has seen (clone detection across domains).
 */
export function verifyPaycap(state, { capability: cap, approval }, { now, signCountFloor = () => 0 }) {
  exactFields(cap, FIELDS, [], 'PAYCAP_FIELDS');
  if (cap.v !== PAYCAP_V) fail('PAYCAP_VERSION');
  if (!UUID.test(cap.capId)) fail('PAYCAP_ID');
  if (cap.accountId !== state.accountId || cap.chainId !== state.chainId) fail('PAYCAP_WRONG_ACCOUNT');
  if (cap.epoch !== String(state.epoch)) fail('STALE_EPOCH', `cap=${cap.epoch} current=${state.epoch}`);
  if (cap.matrixVersion !== state.matrix.version) fail('STALE_MATRIX_VERSION');
  if (cap.purposeId !== state.purpose.purposeId) fail('PAYCAP_WRONG_PURPOSE');
  if (cap.purposeVersion !== state.purpose.version) fail('STALE_PURPOSE_VERSION');
  if (cap.operation !== 'PAY') fail('PAYCAP_OPERATION');
  uint(cap.amountYocto, 'amountYocto'); id(cap.taskRef, 'taskRef');
  if (cap.sku !== '-') id(cap.sku, 'sku');
  if (!/^[0-9a-f]{32}$/.test(cap.nonce)) fail('PAYCAP_NONCE');
  const ia = isoMs(cap.issuedAt, 'issuedAt'), ea = isoMs(cap.expiresAt, 'expiresAt');
  if (ea <= ia) fail('PAYCAP_WINDOW');
  if (ia > now + Number(state.config.skewMs)) fail('PAYCAP_FROM_FUTURE');
  if (now >= ea) fail('PAYCAP_EXPIRED');
  exactFields(approval, ['credId'], ['webauthn', 'sig'], 'PAYCAP_APPROVAL_FIELDS');
  const c = state.creds[approval.credId];
  if (!c) fail('PAYCAP_UNKNOWN_CREDENTIAL');
  if (c.status !== 'active') fail('PAYCAP_CREDENTIAL_NOT_ACTIVE', c.status);
  const rule = state.matrix.rules.PAY;
  if (!rule.anyOf.some(alt => Object.keys(alt).length === 1 && alt[c.role] === '1')) fail('PAYCAP_ROLE_NOT_AUTHORIZED', c.role);
  const dig = paycapDigest(cap);
  let signCount = null;
  if (c.kind === 'passkey') {
    if (!approval.webauthn) fail('PAYCAP_APPROVAL_KIND');
    const r = verifyAssertion(approval.webauthn, { rp: state.rp, expectedChallenge: dig, credential: { ...c.webauthn, signCount: Math.max(c.signCount ?? 0, signCountFloor(c.credId)) }, requireUV: rule.uv === '1' });
    signCount = r.signCount;
  } else {
    if (rule.uv === '1') fail('USER_VERIFICATION_REQUIRED', 'PAY needs a passkey with UV');
    if (!edVerifyDigest(V3_DOMAINS.PAYCAP, dig, approval.sig, c.publicKey)) fail('PAYCAP_BAD_SIGNATURE');
  }
  return { cap, credId: c.credId, signCount, digestHex: dig.toString('hex'), issuedAt: ia, expiresAt: ea };
}
